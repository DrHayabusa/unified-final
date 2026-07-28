from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Body, Depends, FastAPI, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from .auth import (
    constant_time_equal,
    create_session_secrets,
    hash_opaque_token,
    hash_password,
    login_key,
    normalize_email,
    validate_account,
    verify_password,
)
from .config import Settings
from .csv_export import finding_csv, finding_filename
from .database import Database
from .errors import MVAError
from .local_llm import LocalLLMClient
from .repository import Repository, serialize_user
from .validation import (
    ASSET_TYPES,
    clean_text,
    normalize_ai_remediation,
    normalize_asset_ids,
    normalize_asset_payloads,
    normalize_create_payload,
    normalize_customer,
    normalize_memberships,
    normalize_onboarding_tool,
    normalize_team,
    normalize_threat_import,
    normalize_threat_query,
    normalize_uuid_filter,
)

LOGGER = logging.getLogger("mva")
SESSION_COOKIE = "mva_session"
DUMMY_PASSWORD = "MVA-Invalid-Account-Verification-Only!2026"


class MaxBodySizeMiddleware:
    def __init__(self, app, maximum: int):
        self.app = app
        self.maximum = maximum

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            declared = 0
        if declared > self.maximum:
            await self._reject(send)
            return
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.maximum:
                    raise MVAError("The request body exceeds the 32 MB API limit.", 413)
            return message

        try:
            await self.app(scope, limited_receive, send)
        except MVAError as error:
            if error.status_code != 413:
                raise
            await self._reject(send)

    @staticmethod
    async def _reject(send):
        body = b'{"ok":false,"error":"The request body exceeds the 32 MB API limit."}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
            ],
        })
        await send({"type": "http.response.body", "body": body})


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    database = Database(
        settings.database_url,
        settings.database_pool_min,
        settings.database_pool_max,
    )
    repository = Repository(database)
    llm_client = LocalLLMClient(settings)
    dummy_password_hash = hash_password(DUMMY_PASSWORD)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.open()
        LOGGER.info("MVA database initialized.")
        try:
            yield
        finally:
            database.close()

    app = FastAPI(
        title="MVA Unified Vulnerability Management API",
        version="1.0.0",
        docs_url=None if settings.environment == "production" else "/api/docs",
        redoc_url=None,
        openapi_url=None if settings.environment == "production" else "/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.repository = repository
    app.state.llm_client = llm_client
    app.add_middleware(MaxBodySizeMiddleware, maximum=settings.max_request_bytes)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(settings.trusted_hosts) or ["*"],
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-MVA-CSRF"],
        expose_headers=["Content-Disposition"],
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "worker-src 'self' blob:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        if request.url.path.startswith("/api/") or request.url.path == "/health":
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/assets/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            response.headers["Cache-Control"] = "no-cache"
        return response

    @app.exception_handler(MVAError)
    async def mva_error_handler(_: Request, error: MVAError):
        return JSONResponse(
            status_code=error.status_code,
            content={"ok": False, "error": error.message},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_: Request, error: RequestValidationError):
        LOGGER.info("Request validation failed: %s", error.errors())
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "The request payload is invalid."},
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(_: Request, error: Exception):
        LOGGER.exception("Unhandled MVA request failure", exc_info=error)
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "The MVA platform request failed."},
        )

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else ""

    def authenticate(request: Request) -> dict:
        raw_token = request.cookies.get(SESSION_COOKIE)
        if not raw_token:
            raise MVAError("Authentication is required.", 401)
        session = repository.get_session(hash_opaque_token(raw_token))
        if not session:
            raise MVAError("Your session has expired. Sign in again.", 401)
        return session

    def require_write(
        request: Request,
        session: dict = Depends(authenticate),
    ) -> dict:
        csrf = request.headers.get("X-MVA-CSRF", "")
        if not csrf or not constant_time_equal(csrf, session["csrfToken"]):
            raise MVAError(
                "The request security token is invalid. Refresh and try again.",
                403,
            )
        return session

    def require_admin(session: dict = Depends(require_write)) -> dict:
        if session["user"]["globalRole"] != "system_admin":
            raise MVAError("System administrator access is required.", 403)
        return session

    def set_session_cookie(response: Response, token: str) -> None:
        response.set_cookie(
            key=SESSION_COOKIE,
            value=token,
            max_age=settings.session_hours * 3600,
            path="/",
            domain=settings.cookie_domain,
            secure=settings.cookie_secure,
            httponly=True,
            samesite="strict",
        )

    def create_authenticated_session(
        request: Request,
        response: Response,
        user: dict,
    ) -> dict:
        secrets = create_session_secrets()
        repository.create_session(
            user["id"],
            secrets["tokenHash"],
            secrets["csrfToken"],
            request.headers.get("user-agent", ""),
            client_ip(request),
            datetime.now(timezone.utc) + timedelta(hours=settings.session_hours),
        )
        set_session_cookie(response, secrets["token"])
        return {
            "user": user,
            "csrfToken": secrets["csrfToken"],
            "customers": repository.list_customers_for_user(user),
        }

    @app.get("/health")
    def health():
        current = repository.health()
        return {
            "ok": True,
            "service": "mva-python-api",
            "database": current["database"],
            "checkedAt": current["checked_at"],
        }

    @app.get("/api/v1/auth/setup-status")
    def setup_status():
        return {"ok": True, **repository.setup_status()}

    @app.post("/api/v1/auth/bootstrap", status_code=201)
    def bootstrap(
        request: Request,
        response: Response,
        payload: dict = Body(...),
    ):
        account = validate_account(payload)
        user = repository.bootstrap_admin(
            account["email"],
            account["fullName"],
            hash_password(account["password"]),
            client_ip(request),
        )
        repository.mark_login(user["id"])
        return {
            "ok": True,
            **create_authenticated_session(request, response, user),
        }

    @app.post("/api/v1/auth/login")
    def login(
        request: Request,
        response: Response,
        payload: dict = Body(...),
    ):
        email = normalize_email(payload.get("email"))
        rate_key = login_key(client_ip(request), email)
        repository.login_rate_status(rate_key)
        record = repository.get_user_for_login(email)
        password_matches = verify_password(
            str(payload.get("password") or ""),
            record["password_hash"] if record else dummy_password_hash,
        )
        if not record or record["status"] != "active" or not password_matches:
            repository.register_login_failure(rate_key)
            raise MVAError("Email or password is incorrect.", 401)
        repository.clear_login_failures(rate_key)
        repository.mark_login(record["id"])
        user = serialize_user({**record, "last_login_at": datetime.now(timezone.utc)})
        repository.audit(user["id"], None, "auth.login", {}, client_ip(request))
        return {
            "ok": True,
            **create_authenticated_session(request, response, user),
        }

    @app.get("/api/v1/auth/me")
    def current_session(session: dict = Depends(authenticate)):
        return {
            "ok": True,
            "user": session["user"],
            "csrfToken": session["csrfToken"],
            "customers": repository.list_customers_for_user(session["user"]),
        }

    @app.post("/api/v1/auth/logout")
    def logout(
        request: Request,
        response: Response,
        session: dict = Depends(require_write),
    ):
        repository.delete_session(
            hash_opaque_token(request.cookies.get(SESSION_COOKIE, ""))
        )
        response.delete_cookie(
            SESSION_COOKIE,
            path="/",
            domain=settings.cookie_domain,
            secure=settings.cookie_secure,
            httponly=True,
            samesite="strict",
        )
        response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
        return {"ok": True}

    @app.get("/api/v1/llm/status")
    def llm_status(_: dict = Depends(authenticate)):
        return {"ok": True, "llm": llm_client.status()}

    @app.get("/api/v1/customers")
    def customers(session: dict = Depends(authenticate)):
        return {
            "ok": True,
            "customers": repository.list_customers_for_user(session["user"]),
        }

    @app.post("/api/v1/customers", status_code=201)
    def create_customer(
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_admin),
    ):
        customer = repository.create_customer(
            session["user"]["id"],
            normalize_customer(payload),
            client_ip(request),
        )
        return {"ok": True, "customer": customer}

    @app.put("/api/v1/customers/{customer_id}")
    def update_customer(
        customer_id: str,
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_admin),
    ):
        return {
            "ok": True,
            "customer": repository.update_customer(
                session["user"]["id"],
                customer_id,
                normalize_customer(payload),
                client_ip(request),
            ),
        }

    @app.delete("/api/v1/customers/{customer_id}")
    def delete_customer(
        customer_id: str,
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_admin),
    ):
        return {
            "ok": True,
            "deleted": repository.delete_customer(
                session["user"]["id"],
                customer_id,
                str(payload.get("confirmation") or ""),
                client_ip(request),
            ),
        }

    @app.get("/api/v1/customers/{customer_id}/dashboard")
    def customer_dashboard(
        customer_id: str,
        teamId: str = Query(default=""),
        assetId: str = Query(default=""),
        session: dict = Depends(authenticate),
    ):
        access = repository.assert_customer_access(session["user"], customer_id)
        team_id = normalize_uuid_filter(teamId, "Select a valid responsible team.")
        asset_id = normalize_uuid_filter(assetId, "Select a valid asset.")
        return {
            "ok": True,
            "dashboard": repository.get_customer_dashboard(
                customer_id,
                access["assetTypes"],
                team_id,
                asset_id,
            ),
        }

    @app.get("/api/v1/customers/{customer_id}/scan-asset-coverage")
    def scan_asset_coverage(
        customer_id: str,
        session: dict = Depends(authenticate),
    ):
        access = repository.assert_customer_access(session["user"], customer_id)
        return {
            "ok": True,
            "coverage": repository.get_customer_scan_asset_coverage(
                customer_id,
                access["assetTypes"],
            ),
        }

    @app.get("/api/v1/customers/{customer_id}/findings.csv")
    def customer_findings_csv(
        customer_id: str,
        teamId: str = Query(default=""),
        assetId: str = Query(default=""),
        session: dict = Depends(authenticate),
    ):
        access = repository.assert_customer_access(session["user"], customer_id)
        team_id = normalize_uuid_filter(teamId, "Select a valid responsible team.")
        asset_id = normalize_uuid_filter(assetId, "Select a valid asset.")
        exported = repository.get_customer_finding_export(
            customer_id,
            access["assetTypes"],
            team_id,
            asset_id,
        )
        filename = finding_filename(
            exported["customer"]["slug"],
            exported["reportPeriod"],
        )
        return StreamingResponse(
            finding_csv(exported["rows"]),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/v1/customers/{customer_id}/assets")
    def customer_assets(
        customer_id: str,
        limit: int = Query(default=500, ge=1, le=100_000),
        session: dict = Depends(authenticate),
    ):
        access = repository.assert_customer_access(session["user"], customer_id)
        return {
            "ok": True,
            "assets": repository.list_customer_assets(
                customer_id,
                limit,
                access["assetTypes"],
            ),
        }

    @app.get("/api/v1/customers/{customer_id}/teams")
    def customer_teams(
        customer_id: str,
        session: dict = Depends(authenticate),
    ):
        repository.assert_customer_access(session["user"], customer_id)
        return {
            "ok": True,
            "teams": repository.list_customer_teams(customer_id),
        }

    @app.post("/api/v1/customers/{customer_id}/llm/test")
    def test_llm(
        customer_id: str,
        request: Request,
        session: dict = Depends(require_write),
    ):
        repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        result = llm_client.test()
        repository.audit(
            session["user"]["id"],
            customer_id,
            "llm.tested",
            {"model": result["model"]},
            client_ip(request),
        )
        return {"ok": True, "llm": result}

    @app.post("/api/v1/customers/{customer_id}/ai/remediation")
    def ai_remediation(
        customer_id: str,
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        normalized = normalize_ai_remediation(payload)
        generated = llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are the MVA Remediation Guide engine. Return "
                        "customer-ready Markdown only. Never invent commands, "
                        "versions, KB identifiers, CVEs, links, or validation "
                        "evidence. Clearly label unknown values."
                    ),
                },
                {"role": "user", "content": normalized["prompt"]},
            ],
            temperature=0.1,
            max_tokens=12_000,
        )
        repository.audit(
            session["user"]["id"],
            customer_id,
            "llm.remediation_generated",
            {
                "model": generated["model"],
                "targetPeriod": normalized["targetPeriod"],
                "sourceLabel": normalized["sourceLabel"],
            },
            client_ip(request),
        )
        return {
            "ok": True,
            "markdown": generated["content"],
            "model": generated["model"],
            "targetPeriod": normalized["targetPeriod"],
        }

    @app.post(
        "/api/v1/customers/{customer_id}/threat-intel/imports",
    )
    def create_threat_import(
        customer_id: str,
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        imported = repository.create_threat_intel_import(
            customer_id,
            session["user"]["id"],
            normalize_threat_import(payload),
        )
        return JSONResponse(
            status_code=200 if imported["existing"] else 201,
            content=jsonable_encoder({"ok": True, "import": imported}),
        )

    @app.post(
        "/api/v1/customers/{customer_id}/threat-intel/imports/{import_id}/chunks"
    )
    def ingest_threat_chunk(
        customer_id: str,
        import_id: str,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        return {
            "ok": True,
            **repository.ingest_threat_intel_chunk(
                customer_id,
                import_id,
                payload,
            ),
        }

    @app.post(
        "/api/v1/customers/{customer_id}/threat-intel/imports/{import_id}/finalize"
    )
    def finalize_threat_import(
        customer_id: str,
        import_id: str,
        request: Request,
        session: dict = Depends(require_write),
    ):
        repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        imported = repository.finalize_threat_intel_import(
            customer_id,
            import_id,
        )
        repository.audit(
            session["user"]["id"],
            customer_id,
            "threat_intel.imported",
            {
                "importId": imported["id"],
                "records": imported["receivedRecords"],
                "sourceLabel": imported["sourceLabel"],
            },
            client_ip(request),
        )
        return {"ok": True, "import": imported}

    @app.get("/api/v1/customers/{customer_id}/threat-intel")
    def search_threat_intel(
        customer_id: str,
        q: str = Query(default=""),
        limit: int = Query(default=100, ge=1, le=500),
        session: dict = Depends(authenticate),
    ):
        repository.assert_customer_access(session["user"], customer_id)
        query = normalize_threat_query(q) if q.strip() else ""
        return {
            "ok": True,
            "records": repository.search_threat_intel(
                customer_id,
                query,
                limit,
            ),
        }

    @app.post("/api/v1/customers/{customer_id}/threat-intel/enrich")
    def enrich_threat_intel(
        customer_id: str,
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        query = normalize_threat_query(payload.get("query"))
        records = repository.search_threat_intel(customer_id, query, 30)
        generated = llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a defensive vulnerability intelligence analyst "
                        "operating on private scanner evidence. Return one valid "
                        "JSON object only. Never invent CVEs, affected versions, "
                        "patches, exploit status, commands, or links. Use Unknown "
                        "when evidence is absent."
                    ),
                },
                {"role": "user", "content": _threat_intel_prompt(query, records)},
            ],
            json_mode=True,
            temperature=0,
            max_tokens=4096,
        )
        saved = repository.save_threat_intel_enrichment(
            session["user"]["id"],
            customer_id,
            {
                "query": query,
                "model": generated["model"],
                "evidenceCount": len(records),
                "responseText": generated["content"],
            },
        )
        repository.audit(
            session["user"]["id"],
            customer_id,
            "threat_intel.enriched",
            {
                "query": query,
                "model": generated["model"],
                "evidenceCount": len(records),
                "enrichmentId": saved["id"],
            },
            client_ip(request),
        )
        return {
            "ok": True,
            "content": generated["content"],
            "model": generated["model"],
            "evidenceCount": len(records),
            "records": records,
        }

    @app.post("/api/v1/customers/{customer_id}/teams", status_code=201)
    def create_team(
        customer_id: str,
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        return {
            "ok": True,
            "team": repository.create_customer_team(
                session["user"]["id"],
                customer_id,
                normalize_team(payload),
                client_ip(request),
            ),
        }

    @app.put("/api/v1/customers/{customer_id}/teams/{team_id}")
    def update_team(
        customer_id: str,
        team_id: str,
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        return {
            "ok": True,
            "team": repository.update_customer_team(
                session["user"]["id"],
                customer_id,
                team_id,
                normalize_team(payload),
                client_ip(request),
            ),
        }

    @app.post("/api/v1/customers/{customer_id}/assets")
    def import_assets(
        customer_id: str,
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        access = repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        assets = normalize_asset_payloads(payload)
        _assert_asset_type_access(assets, access["assetTypes"])
        return {
            "ok": True,
            **repository.upsert_customer_assets(
                session["user"]["id"],
                customer_id,
                assets,
                client_ip(request),
            ),
        }

    @app.delete("/api/v1/customers/{customer_id}/assets")
    def delete_assets(
        customer_id: str,
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        return {
            "ok": True,
            **repository.delete_customer_assets(
                session["user"]["id"],
                customer_id,
                normalize_asset_ids(payload),
                client_ip(request),
            ),
        }

    @app.patch("/api/v1/customers/{customer_id}/assets/{asset_id}")
    def update_asset(
        customer_id: str,
        asset_id: str,
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        access = repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        has_asset_type = "assetType" in payload
        asset_type = payload.get("assetType") if has_asset_type else None
        if has_asset_type and asset_type not in ASSET_TYPES:
            raise MVAError("Select a valid asset category.")
        if asset_type and access["assetTypes"] and asset_type not in access["assetTypes"]:
            raise MVAError(
                "This asset category is outside your account scope.",
                403,
            )
        has_team_id = "teamId" in payload
        team_id = payload.get("teamId") if has_team_id else None
        if team_id:
            team_id = normalize_uuid_filter(
                team_id,
                "Select a valid responsible team.",
            )
        changes = {
            "hasInScope": isinstance(payload.get("inScope"), bool),
            "inScope": payload.get("inScope"),
            "hasAssetType": has_asset_type,
            "assetType": asset_type,
            "hasTeamId": has_team_id,
            "teamId": team_id,
            "hasOnboardingTool": "onboardingTool" in payload,
            "onboardingTool": (
                normalize_onboarding_tool(payload.get("onboardingTool"))
                if "onboardingTool" in payload
                else None
            ),
            "hasPlatform": "platform" in payload,
            "platform": (
                clean_text(payload.get("platform"), 2000)
                if "platform" in payload
                else None
            ),
            "hasIpAddress": "ipAddress" in payload,
            "ipAddress": (
                clean_text(payload.get("ipAddress"), 500)
                if "ipAddress" in payload
                else None
            ),
            "hasDnsName": "dnsName" in payload,
            "dnsName": (
                clean_text(payload.get("dnsName"), 1000).lower()
                if "dnsName" in payload
                else None
            ),
            "hasHostName": "hostName" in payload,
            "hostName": (
                clean_text(payload.get("hostName"), 1000).lower()
                if "hostName" in payload
                else None
            ),
        }
        return {
            "ok": True,
            "asset": repository.update_customer_asset(
                session["user"]["id"],
                customer_id,
                asset_id,
                changes,
                client_ip(request),
            ),
        }

    @app.get("/api/v1/admin/users")
    def users(session: dict = Depends(authenticate)):
        if session["user"]["globalRole"] != "system_admin":
            raise MVAError("System administrator access is required.", 403)
        return {"ok": True, "users": repository.list_users()}

    @app.post("/api/v1/admin/users", status_code=201)
    def create_user(
        request: Request,
        payload: dict = Body(...),
        session: dict = Depends(require_admin),
    ):
        account = validate_account(payload)
        global_role = (
            "system_admin"
            if payload.get("globalRole") == "system_admin"
            else "customer_user"
        )
        memberships = normalize_memberships(payload.get("memberships"))
        if global_role == "customer_user" and not memberships:
            raise MVAError("Assign a customer user to at least one customer.")
        return {
            "ok": True,
            "user": repository.create_user(
                session["user"]["id"],
                account["email"],
                account["fullName"],
                hash_password(account["password"]),
                global_role,
                memberships,
                client_ip(request),
            ),
        }

    @app.post("/api/v1/customers/{customer_id}/scan-runs")
    def create_scan_run(
        customer_id: str,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        access = repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        metadata = normalize_create_payload(
            payload,
            access["customer"]["name"],
        )
        run = repository.create_scan_run(
            customer_id,
            session["user"]["id"],
            metadata,
        )
        return JSONResponse(
            status_code=200 if run["existing"] else 201,
            content=jsonable_encoder({"ok": True, "run": run}),
        )

    @app.post("/api/v1/customers/{customer_id}/scan-runs/{run_id}/chunks")
    def ingest_scan_chunk(
        customer_id: str,
        run_id: str,
        payload: dict = Body(...),
        session: dict = Depends(require_write),
    ):
        access = repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        return {
            "ok": True,
            **repository.ingest_chunk(
                customer_id,
                run_id,
                payload,
                access["assetTypes"],
            ),
        }

    @app.post("/api/v1/customers/{customer_id}/scan-runs/{run_id}/finalize")
    def finalize_scan_run(
        customer_id: str,
        run_id: str,
        request: Request,
        session: dict = Depends(require_write),
    ):
        repository.assert_customer_access(
            session["user"],
            customer_id,
            ("owner", "analyst"),
        )
        run = repository.finalize_scan_run(customer_id, run_id)
        repository.audit(
            session["user"]["id"],
            customer_id,
            "scan.finalized",
            {"scanRunId": run_id},
            client_ip(request),
        )
        return {"ok": True, "run": run}

    @app.get("/api/v1/customers/{customer_id}/scan-runs")
    def list_scan_runs(
        customer_id: str,
        limit: int = Query(default=20, ge=1, le=100),
        session: dict = Depends(authenticate),
    ):
        access = repository.assert_customer_access(session["user"], customer_id)
        return {
            "ok": True,
            "runs": repository.list_scan_runs(
                customer_id,
                limit,
                access["assetTypes"],
            ),
        }

    @app.get("/api/v1/customers/{customer_id}/scan-runs/{run_id}")
    def get_scan_run(
        customer_id: str,
        run_id: str,
        session: dict = Depends(authenticate),
    ):
        access = repository.assert_customer_access(session["user"], customer_id)
        return {
            "ok": True,
            "run": repository.get_scan_run(
                customer_id,
                run_id,
                access["assetTypes"],
            ),
        }

    @app.get("/{requested_path:path}", include_in_schema=False)
    def frontend(requested_path: str):
        if requested_path == "api" or requested_path.startswith("api/"):
            raise MVAError("The requested API endpoint does not exist.", 404)
        frontend_root = settings.frontend_dist.resolve()
        relative = requested_path or "index.html"
        candidate = (frontend_root / relative).resolve()
        if (
            frontend_root in candidate.parents
            and candidate.is_file()
            and candidate.name != "index.html"
        ):
            return FileResponse(candidate)
        index = frontend_root / "index.html"
        if index.is_file():
            return FileResponse(index)
        raise MVAError("The frontend build is not available.", 404)

    return app


def _assert_asset_type_access(assets: list[dict], asset_types: list[str]) -> None:
    if not asset_types:
        return
    blocked = next(
        (asset for asset in assets if asset["assetType"] not in asset_types),
        None,
    )
    if blocked:
        raise MVAError(
            f"This account is limited to {', '.join(asset_types)} assets and "
            f"cannot modify {blocked['assetType']} inventory.",
            403,
        )


def _threat_intel_prompt(query: str, records: list[dict]) -> str:
    evidence = [
        {
            "cve": record["cve"],
            "vulnerabilityName": record["vulnerabilityName"],
            "sourceTool": record["sourceTool"],
            "sourceVulnerabilityId": record["sourceVulnerabilityId"],
            "severity": record["severity"],
            "patchPriority": record["patchPriority"],
            "exploitAvailable": record["exploitAvailable"],
            "vulnerabilityConfidence": record["vulnerabilityConfidence"],
            "exploitEvidence": record["exploitEvidence"],
            "description": record["description"],
            "remediation": record["remediation"],
            "kbLinks": record["kbLinks"],
            "product": record["product"],
            "platformDetails": record["platformDetails"],
            "firstObserved": record["firstObserved"],
            "lastObserved": record["lastObserved"],
        }
        for record in records
    ]
    import json

    return (
        f"Investigate: {query}\n\n"
        "Return JSON keys:\n"
        "summary, highestSeverity, cvss, cves, affectedProducts, "
        "affectedVersions, exploitAvailable, exploitEvidence, attackPath, "
        "patches, remediationSteps, detectionSteps, references.\n\n"
        "Rules:\n"
        "- Treat the supplied scanner evidence as the primary source.\n"
        "- Distinguish confirmed facts from model inference.\n"
        "- Use only HTTPS references present in the evidence.\n"
        "- Do not provide exploit payloads or offensive execution steps.\n"
        '- Use "Unknown" or an empty array where evidence is insufficient.\n\n'
        "Tenant scanner evidence:\n"
        f"{json.dumps(evidence, indent=2, default=str)}"
    )


app = create_app()
