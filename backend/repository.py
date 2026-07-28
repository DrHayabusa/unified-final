from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from psycopg import errors as pg_errors
from psycopg.types.json import Jsonb

from .database import Database
from .errors import MVAError
from .validation import normalize_chunk_payload, normalize_threat_chunk


class Repository:
    def __init__(self, database: Database):
        self.database = database

    def health(self) -> dict:
        return self.database.health()

    def setup_status(self) -> dict:
        row = self._one("SELECT count(*)::integer AS user_count FROM users")
        return {"setupRequired": row["user_count"] == 0}

    def bootstrap_admin(self, email: str, full_name: str, password_hash: str, ip_address: str) -> dict:
        with self.database.pool.connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_advisory_xact_lock(741852963)")
                    cursor.execute("SELECT count(*)::integer AS user_count FROM users")
                    if cursor.fetchone()["user_count"] > 0:
                        raise MVAError("Initial administrator setup has already been completed.", 409)
                    cursor.execute(
                        """INSERT INTO users (email, full_name, password_hash, global_role)
                           VALUES (%s, %s, %s, 'system_admin')
                           RETURNING id, email, full_name, global_role, status, created_at, last_login_at""",
                        (email, full_name, password_hash),
                    )
                    user = cursor.fetchone()
                    cursor.execute(
                        """INSERT INTO audit_events (actor_user_id, event_type, event_data, ip_address)
                           VALUES (%s, 'auth.bootstrap_admin', %s, %s)""",
                        (user["id"], Jsonb({"email": email}), ip_address[:200]),
                    )
        return serialize_user(user)

    def get_user_for_login(self, email: str) -> dict | None:
        return self._one(
            """SELECT id, email, full_name, password_hash, global_role, status, created_at, last_login_at
               FROM users WHERE email = %s""",
            (email,),
        )

    def mark_login(self, user_id) -> None:
        self._execute("UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = %s", (user_id,))

    def login_rate_status(self, key_hash: str, limit: int = 8) -> None:
        with self.database.pool.connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute("DELETE FROM auth_login_attempts WHERE reset_at <= now()")
                    cursor.execute(
                        "SELECT failure_count FROM auth_login_attempts WHERE key_hash = %s",
                        (key_hash,),
                    )
                    row = cursor.fetchone()
                    if row and row["failure_count"] >= limit:
                        raise MVAError("Too many sign-in attempts. Try again later.", 429)

    def register_login_failure(self, key_hash: str, window_minutes: int = 15) -> None:
        reset_at = datetime.now(timezone.utc) + timedelta(minutes=window_minutes)
        self._execute(
            """INSERT INTO auth_login_attempts (key_hash, failure_count, reset_at)
               VALUES (%s, 1, %s)
               ON CONFLICT (key_hash) DO UPDATE SET
                 failure_count = CASE
                   WHEN auth_login_attempts.reset_at <= now() THEN 1
                   ELSE auth_login_attempts.failure_count + 1
                 END,
                 reset_at = CASE
                   WHEN auth_login_attempts.reset_at <= now() THEN EXCLUDED.reset_at
                   ELSE auth_login_attempts.reset_at
                 END,
                 updated_at = now()""",
            (key_hash, reset_at),
        )

    def clear_login_failures(self, key_hash: str) -> None:
        self._execute("DELETE FROM auth_login_attempts WHERE key_hash = %s", (key_hash,))

    def create_session(
        self,
        user_id,
        token_hash: str,
        csrf_token: str,
        user_agent: str,
        ip_address: str,
        expires_at: datetime,
    ) -> None:
        with self.database.pool.connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute("DELETE FROM auth_sessions WHERE expires_at <= now()")
                    cursor.execute(
                        """INSERT INTO auth_sessions
                           (user_id, token_hash, csrf_token, user_agent, ip_address, expires_at)
                           VALUES (%s, %s, %s, %s, %s, %s)""",
                        (user_id, token_hash, csrf_token, user_agent[:1000], ip_address[:200], expires_at),
                    )

    def get_session(self, token_hash: str) -> dict | None:
        row = self._one(
            """UPDATE auth_sessions session
               SET last_seen_at = now()
               FROM users user_account
               WHERE session.token_hash = %s
                 AND session.user_id = user_account.id
                 AND session.expires_at > now()
                 AND user_account.status = 'active'
               RETURNING session.id AS session_id, session.csrf_token, session.expires_at,
                         user_account.id, user_account.email, user_account.full_name,
                         user_account.global_role, user_account.status, user_account.created_at,
                         user_account.last_login_at""",
            (token_hash,),
        )
        if not row:
            return None
        return {
            "sessionId": row["session_id"],
            "csrfToken": row["csrf_token"],
            "expiresAt": row["expires_at"],
            "user": serialize_user(row),
        }

    def delete_session(self, token_hash: str) -> None:
        self._execute("DELETE FROM auth_sessions WHERE token_hash = %s", (token_hash,))

    def list_customers_for_user(self, user: dict) -> list[dict]:
        if user["globalRole"] == "system_admin":
            rows = self._all(
                """SELECT customer.*, 'system_admin'::text AS membership_role,
                          ARRAY[]::text[] AS asset_type_scope,
                          (SELECT count(*)::integer FROM customer_assets asset
                           WHERE asset.customer_id = customer.id AND asset.in_scope) AS asset_count,
                          (SELECT count(*)::integer FROM scan_runs run
                           WHERE run.customer_id = customer.id AND run.status = 'ready') AS scan_count
                   FROM customers customer
                   ORDER BY customer.status, customer.name"""
            )
        else:
            rows = self._all(
                """SELECT customer.*, membership.role AS membership_role,
                          membership.asset_types AS asset_type_scope,
                          (SELECT count(*)::integer FROM customer_assets asset
                           WHERE asset.customer_id = customer.id AND asset.in_scope
                             AND (cardinality(membership.asset_types) = 0
                                  OR asset.asset_type = ANY(membership.asset_types))) AS asset_count,
                          (SELECT count(*)::integer FROM scan_runs run
                           WHERE run.customer_id = customer.id AND run.status = 'ready') AS scan_count
                   FROM customer_memberships membership
                   JOIN customers customer ON customer.id = membership.customer_id
                   WHERE membership.user_id = %s
                   ORDER BY customer.status, customer.name""",
                (user["id"],),
            )
        return [serialize_customer(row) for row in rows]

    def assert_customer_access(
        self,
        user: dict,
        customer_id: str,
        allowed_roles: tuple[str, ...] = ("owner", "analyst", "viewer"),
    ) -> dict:
        customer = self._one("SELECT * FROM customers WHERE id = %s AND status = 'active'", (customer_id,))
        if not customer:
            raise MVAError("Customer was not found or is inactive.", 404)
        if user["globalRole"] == "system_admin":
            return {"customer": serialize_customer(customer), "role": "system_admin", "assetTypes": []}
        membership = self._one(
            "SELECT role, asset_types FROM customer_memberships WHERE customer_id = %s AND user_id = %s",
            (customer_id, user["id"]),
        )
        if not membership or membership["role"] not in allowed_roles:
            raise MVAError("You do not have access to this customer.", 403)
        customer["membership_role"] = membership["role"]
        customer["asset_type_scope"] = membership["asset_types"] or []
        return {
            "customer": serialize_customer(customer),
            "role": membership["role"],
            "assetTypes": membership["asset_types"] or [],
        }

    def create_customer(self, actor_user_id, payload: dict, ip_address: str) -> dict:
        try:
            row = self._one(
                """INSERT INTO customers (name, slug, asset_scope_mode, notes, status)
                   VALUES (%s, %s, %s, %s, %s) RETURNING *""",
                (payload["name"], payload["slug"], payload["assetScopeMode"], payload["notes"], payload["status"]),
            )
        except pg_errors.UniqueViolation as error:
            raise MVAError("A customer with this identifier already exists.", 409) from error
        self.audit(actor_user_id, row["id"], "customer.created", {
            "name": payload["name"],
            "assetScopeMode": payload["assetScopeMode"],
        }, ip_address)
        return serialize_customer(row)

    def update_customer(self, actor_user_id, customer_id: str, payload: dict, ip_address: str) -> dict:
        try:
            row = self._one(
                """UPDATE customers SET name = %s, slug = %s, asset_scope_mode = %s,
                          notes = %s, status = %s, updated_at = now()
                   WHERE id = %s RETURNING *""",
                (payload["name"], payload["slug"], payload["assetScopeMode"], payload["notes"], payload["status"], customer_id),
            )
        except pg_errors.UniqueViolation as error:
            raise MVAError("A customer with this identifier already exists.", 409) from error
        if not row:
            raise MVAError("Customer was not found.", 404)
        self.audit(actor_user_id, customer_id, "customer.updated", {
            "name": payload["name"],
            "assetScopeMode": payload["assetScopeMode"],
            "status": payload["status"],
        }, ip_address)
        return serialize_customer(row)

    def delete_customer(self, actor_user_id, customer_id: str, confirmation: str, ip_address: str) -> dict:
        with self.database.pool.connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute("SELECT id, name, slug FROM customers WHERE id = %s FOR UPDATE", (customer_id,))
                    customer = cursor.fetchone()
                    if not customer:
                        raise MVAError("Tenant was not found.", 404)
                    if confirmation != customer["name"]:
                        raise MVAError("Type the exact tenant name to confirm deletion.", 409)
                    cursor.execute(
                        """SELECT
                             (SELECT count(*)::integer FROM scan_runs WHERE customer_id = %s) AS reports,
                             (SELECT count(*)::integer FROM customer_assets WHERE customer_id = %s) AS assets,
                             (SELECT count(*)::integer FROM customer_memberships WHERE customer_id = %s) AS memberships""",
                        (customer_id, customer_id, customer_id),
                    )
                    counts = cursor.fetchone()
                    cursor.execute(
                        """INSERT INTO audit_events
                           (actor_user_id, customer_id, event_type, event_data, ip_address)
                           VALUES (%s, %s, 'customer.deleted', %s, %s)""",
                        (actor_user_id, customer_id, Jsonb({
                            "customerId": customer_id,
                            "name": customer["name"],
                            "slug": customer["slug"],
                            **counts,
                        }), ip_address[:200]),
                    )
                    cursor.execute("DELETE FROM customers WHERE id = %s", (customer_id,))
        return {"id": customer_id, "name": customer["name"], "slug": customer["slug"], **counts}

    def list_users(self) -> list[dict]:
        rows = self._all(
            """SELECT user_account.id, user_account.email, user_account.full_name,
                      user_account.global_role, user_account.status, user_account.created_at,
                      user_account.last_login_at,
                      COALESCE(jsonb_agg(jsonb_build_object(
                        'customerId', membership.customer_id,
                        'role', membership.role,
                        'assetTypes', membership.asset_types
                      )) FILTER (WHERE membership.customer_id IS NOT NULL), '[]'::jsonb) AS memberships
               FROM users user_account
               LEFT JOIN customer_memberships membership ON membership.user_id = user_account.id
               GROUP BY user_account.id
               ORDER BY user_account.created_at DESC"""
        )
        return [{**serialize_user(row), "memberships": row["memberships"] or []} for row in rows]

    def create_user(
        self,
        actor_user_id,
        email: str,
        full_name: str,
        password_hash: str,
        global_role: str,
        memberships: list[dict],
        ip_address: str,
    ) -> dict:
        try:
            with self.database.pool.connection() as connection:
                with connection.transaction():
                    with connection.cursor() as cursor:
                        cursor.execute(
                            """INSERT INTO users (email, full_name, password_hash, global_role)
                               VALUES (%s, %s, %s, %s)
                               RETURNING id, email, full_name, global_role, status, created_at, last_login_at""",
                            (email, full_name, password_hash, global_role),
                        )
                        user = cursor.fetchone()
                        for membership in memberships:
                            cursor.execute(
                                """INSERT INTO customer_memberships
                                   (customer_id, user_id, role, asset_types)
                                   VALUES (%s, %s, %s, %s)
                                   ON CONFLICT (customer_id, user_id) DO UPDATE SET
                                     role = EXCLUDED.role, asset_types = EXCLUDED.asset_types""",
                                (membership["customerId"], user["id"], membership["role"], membership["assetTypes"]),
                            )
                        cursor.execute(
                            """INSERT INTO audit_events
                               (actor_user_id, event_type, event_data, ip_address)
                               VALUES (%s, 'user.created', %s, %s)""",
                            (actor_user_id, Jsonb({
                                "userId": str(user["id"]),
                                "email": email,
                                "globalRole": global_role,
                            }), ip_address[:200]),
                        )
        except pg_errors.UniqueViolation as error:
            raise MVAError("A user with this email already exists.", 409) from error
        except pg_errors.ForeignKeyViolation as error:
            raise MVAError("One or more selected customers do not exist.") from error
        return serialize_user(user)

    def list_customer_teams(self, customer_id: str) -> list[dict]:
        rows = self._all(
            """SELECT team.id, team.customer_id, team.name, team.code, team.description,
                      team.created_at, team.updated_at,
                      count(asset.id)::integer AS asset_count,
                      count(asset.id) FILTER (WHERE asset.in_scope)::integer AS in_scope_asset_count
               FROM customer_teams team
               LEFT JOIN customer_assets asset
                 ON asset.team_id = team.id AND asset.customer_id = team.customer_id
               WHERE team.customer_id = %s
               GROUP BY team.id ORDER BY team.name""",
            (customer_id,),
        )
        return [serialize_team(row) for row in rows]

    def create_customer_team(self, actor_user_id, customer_id: str, payload: dict, ip_address: str) -> dict:
        try:
            row = self._one(
                """INSERT INTO customer_teams (customer_id, name, code, description)
                   VALUES (%s, %s, %s, %s) RETURNING *""",
                (customer_id, payload["name"], payload["code"], payload["description"]),
            )
        except pg_errors.UniqueViolation as error:
            raise MVAError("A team with this name or code already exists for the customer.", 409) from error
        self.audit(actor_user_id, customer_id, "team.created", {"teamId": str(row["id"]), "name": payload["name"]}, ip_address)
        return serialize_team(row)

    def update_customer_team(
        self,
        actor_user_id,
        customer_id: str,
        team_id: str,
        payload: dict,
        ip_address: str,
    ) -> dict:
        try:
            row = self._one(
                """UPDATE customer_teams SET name = %s, code = %s, description = %s, updated_at = now()
                   WHERE customer_id = %s AND id = %s RETURNING *""",
                (payload["name"], payload["code"], payload["description"], customer_id, team_id),
            )
        except pg_errors.UniqueViolation as error:
            raise MVAError("A team with this name or code already exists for the customer.", 409) from error
        if not row:
            raise MVAError("Team was not found.", 404)
        self.audit(actor_user_id, customer_id, "team.updated", {"teamId": team_id, "name": payload["name"]}, ip_address)
        return serialize_team(row)

    def list_customer_assets(self, customer_id: str, limit: int = 500, asset_types: list[str] | None = None) -> list[dict]:
        rows = self._all(
            """SELECT asset.id, asset.asset_key, asset.ip_address, asset.dns_name,
                      asset.host_name, asset.external_id, asset.asset_type,
                      asset.onboarding_tool, asset.team_id, team.name AS team_name,
                      asset.platform, asset.business_unit, asset.criticality,
                      asset.internet_exposed, asset.origin, asset.in_scope,
                      asset.first_seen_at, asset.last_seen_at, asset.updated_at
               FROM customer_assets asset
               LEFT JOIN customer_teams team
                 ON team.id = asset.team_id AND team.customer_id = asset.customer_id
               WHERE asset.customer_id = %s
                 AND (cardinality(%s::text[]) = 0 OR asset.asset_type = ANY(%s::text[]))
               ORDER BY asset.in_scope DESC, asset.origin,
                        COALESCE(NULLIF(asset.dns_name, ''), NULLIF(asset.host_name, ''),
                                 asset.ip_address, asset.asset_key)
               LIMIT %s""",
            (customer_id, asset_types or [], asset_types or [], limit),
        )
        return [serialize_asset(row) for row in rows]

    def upsert_customer_assets(
        self,
        actor_user_id,
        customer_id: str,
        assets: list[dict],
        ip_address: str,
    ) -> dict:
        with self.database.pool.connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    team_ids = {asset["teamId"] for asset in assets if asset.get("teamId")}
                    if team_ids:
                        cursor.execute(
                            "SELECT id::text FROM customer_teams WHERE customer_id = %s AND id = ANY(%s::uuid[])",
                            (customer_id, list(team_ids)),
                        )
                        found = {str(row["id"]) for row in cursor.fetchall()}
                        if found != team_ids:
                            raise MVAError("One or more assets reference a team outside this customer.")
                    for asset in assets:
                        cursor.execute(
                            """INSERT INTO customer_assets (
                                 customer_id, asset_key, ip_address, dns_name, host_name, external_id,
                                 asset_type, onboarding_tool, team_id, platform, business_unit,
                                 criticality, internet_exposed, origin, in_scope
                               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'manual', true)
                               ON CONFLICT (customer_id, asset_key) DO UPDATE SET
                                 ip_address = EXCLUDED.ip_address,
                                 dns_name = EXCLUDED.dns_name,
                                 host_name = EXCLUDED.host_name,
                                 external_id = EXCLUDED.external_id,
                                 asset_type = EXCLUDED.asset_type,
                                 onboarding_tool = EXCLUDED.onboarding_tool,
                                 team_id = EXCLUDED.team_id,
                                 platform = EXCLUDED.platform,
                                 business_unit = EXCLUDED.business_unit,
                                 criticality = EXCLUDED.criticality,
                                 internet_exposed = EXCLUDED.internet_exposed,
                                 origin = 'manual', in_scope = true,
                                 last_seen_at = now(), updated_at = now()
                               RETURNING id""",
                            (
                                customer_id, asset["assetKey"], asset["ipAddress"], asset["dnsName"],
                                asset["hostName"], asset["externalId"], asset["assetType"],
                                asset["onboardingTool"], asset["teamId"], asset["platform"],
                                asset["businessUnit"], asset["criticality"], asset["internetExposed"],
                            ),
                        )
                        asset_id = cursor.fetchone()["id"]
                        aliases = {
                            str(value).strip().lower()
                            for value in (
                                asset["assetKey"], asset["ipAddress"], asset["dnsName"],
                                asset["hostName"], asset["externalId"],
                            )
                            if value
                        }
                        for alias in aliases:
                            cursor.execute(
                                """INSERT INTO customer_asset_aliases (customer_id, asset_id, alias)
                                   VALUES (%s, %s, %s)
                                   ON CONFLICT (customer_id, alias) DO UPDATE SET asset_id = EXCLUDED.asset_id""",
                                (customer_id, asset_id, alias),
                            )
                    cursor.execute(
                        """INSERT INTO audit_events
                           (actor_user_id, customer_id, event_type, event_data, ip_address)
                           VALUES (%s, %s, 'assets.upserted', %s, %s)""",
                        (actor_user_id, customer_id, Jsonb({"count": len(assets)}), ip_address[:200]),
                    )
        return {"count": len(assets)}

    def delete_customer_assets(
        self,
        actor_user_id,
        customer_id: str,
        asset_ids: list[str],
        ip_address: str,
    ) -> dict:
        with self.database.pool.connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        """DELETE FROM customer_assets
                           WHERE customer_id = %s AND id = ANY(%s::uuid[]) RETURNING id""",
                        (customer_id, asset_ids),
                    )
                    deleted = cursor.fetchall()
                    if len(deleted) != len(asset_ids):
                        raise MVAError("One or more selected assets were not found in this tenant.", 404)
                    cursor.execute(
                        """INSERT INTO audit_events
                           (actor_user_id, customer_id, event_type, event_data, ip_address)
                           VALUES (%s, %s, 'assets.deleted', %s, %s)""",
                        (actor_user_id, customer_id, Jsonb({
                            "count": len(deleted),
                            "assetIds": asset_ids,
                        }), ip_address[:200]),
                    )
        return {"count": len(deleted)}

    def update_customer_asset(
        self,
        actor_user_id,
        customer_id: str,
        asset_id: str,
        changes: dict,
        ip_address: str,
    ) -> dict:
        try:
            with self.database.pool.connection() as connection:
                with connection.transaction():
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT * FROM customer_assets WHERE id = %s AND customer_id = %s FOR UPDATE",
                            (asset_id, customer_id),
                        )
                        current = cursor.fetchone()
                        if not current:
                            raise MVAError("Asset was not found.", 404)
                        if changes.get("hasTeamId") and changes.get("teamId"):
                            cursor.execute(
                                "SELECT id FROM customer_teams WHERE id = %s AND customer_id = %s",
                                (changes["teamId"], customer_id),
                            )
                            if not cursor.fetchone():
                                raise MVAError("Responsible team was not found in this tenant.", 404)
                        ip_value = changes.get("ipAddress") if changes.get("hasIpAddress") else current["ip_address"]
                        dns_value = changes.get("dnsName") if changes.get("hasDnsName") else current["dns_name"]
                        host_value = changes.get("hostName") if changes.get("hasHostName") else current["host_name"]
                        asset_key = str(ip_value or dns_value or host_value or current["external_id"]).strip().lower()
                        if not asset_key:
                            raise MVAError("An asset needs an IP address or host name.")
                        aliases = list(dict.fromkeys(
                            str(value).strip().lower()
                            for value in (asset_key, ip_value, dns_value, host_value, current["external_id"])
                            if value
                        ))
                        cursor.execute(
                            """SELECT alias FROM customer_asset_aliases
                               WHERE customer_id = %s AND asset_id <> %s AND alias = ANY(%s::text[])
                               LIMIT 1""",
                            (customer_id, asset_id, aliases),
                        )
                        collision = cursor.fetchone()
                        if collision:
                            raise MVAError(f"Asset identity '{collision['alias']}' already belongs to another asset.", 409)
                        cursor.execute(
                            """UPDATE customer_assets SET
                                 asset_key = %s, ip_address = %s, dns_name = %s, host_name = %s,
                                 in_scope = CASE WHEN %s THEN %s ELSE in_scope END,
                                 asset_type = CASE WHEN %s THEN %s ELSE asset_type END,
                                 team_id = CASE WHEN %s THEN %s::uuid ELSE team_id END,
                                 onboarding_tool = CASE WHEN %s THEN %s ELSE onboarding_tool END,
                                 platform = CASE WHEN %s THEN %s ELSE platform END,
                                 updated_at = now()
                               WHERE id = %s AND customer_id = %s RETURNING *""",
                            (
                                asset_key, ip_value, dns_value, host_value,
                                changes.get("hasInScope", False), changes.get("inScope"),
                                changes.get("hasAssetType", False), changes.get("assetType"),
                                changes.get("hasTeamId", False), changes.get("teamId"),
                                changes.get("hasOnboardingTool", False), changes.get("onboardingTool"),
                                changes.get("hasPlatform", False), changes.get("platform"),
                                asset_id, customer_id,
                            ),
                        )
                        updated = cursor.fetchone()
                        cursor.execute(
                            "DELETE FROM customer_asset_aliases WHERE customer_id = %s AND asset_id = %s",
                            (customer_id, asset_id),
                        )
                        for alias in aliases:
                            cursor.execute(
                                "INSERT INTO customer_asset_aliases (customer_id, asset_id, alias) VALUES (%s, %s, %s)",
                                (customer_id, asset_id, alias),
                            )
                        cursor.execute(
                            """INSERT INTO audit_events
                               (actor_user_id, customer_id, event_type, event_data, ip_address)
                               VALUES (%s, %s, 'asset.updated', %s, %s)""",
                            (actor_user_id, customer_id, Jsonb({"assetId": asset_id, **changes}), ip_address[:200]),
                        )
            team_name = ""
            if updated["team_id"]:
                team = self._one("SELECT name FROM customer_teams WHERE id = %s", (updated["team_id"],))
                team_name = team["name"] if team else ""
            updated["team_name"] = team_name
            return serialize_asset(updated)
        except pg_errors.UniqueViolation as error:
            raise MVAError("Another asset already uses this IP address or host name.", 409) from error

    def create_scan_run(self, customer_id: str, created_by, metadata: dict) -> dict:
        run_id = str(uuid4())
        inserted = self._one(
            """INSERT INTO scan_runs (
                 id, tenant_key, customer_id, created_by, customer_name, ingestion_key,
                 workflow, source_tool, source_label, report_period, file_names,
                 source_ids, expected_findings, expected_chunks, dashboard, input_summary
               ) VALUES (
                 %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
               )
               ON CONFLICT (customer_id, ingestion_key) DO NOTHING
               RETURNING *""",
            (
                run_id,
                customer_id,
                customer_id,
                created_by,
                metadata["customerName"],
                metadata["ingestionKey"],
                metadata["workflow"],
                metadata["sourceTool"],
                metadata["sourceLabel"],
                metadata["reportPeriod"],
                metadata["fileNames"],
                metadata["sourceIds"],
                metadata["expectedFindings"],
                metadata["expectedChunks"],
                Jsonb(metadata["dashboard"]),
                Jsonb(metadata["inputSummary"]),
            ),
        )
        if inserted:
            return {**serialize_run(inserted), "existing": False}
        existing = self._one(
            "SELECT * FROM scan_runs WHERE customer_id = %s AND ingestion_key = %s",
            (customer_id, metadata["ingestionKey"]),
        )
        return {**serialize_run(existing), "existing": True}

    def ingest_chunk(
        self,
        customer_id: str,
        scan_run_id: str,
        payload: dict,
        asset_types: list[str] | None = None,
    ) -> dict:
        asset_types = asset_types or []
        with self.database.pool.connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT * FROM scan_runs WHERE id = %s AND customer_id = %s FOR UPDATE",
                        (scan_run_id, customer_id),
                    )
                    run = cursor.fetchone()
                    if not run:
                        raise MVAError("Scan run was not found.", 404)
                    chunk = normalize_chunk_payload(payload, run["expected_findings"])
                    if chunk["chunkIndex"] >= run["expected_chunks"]:
                        raise MVAError("Chunk index exceeds the declared chunk count.")
                    if asset_types:
                        self._assert_findings_match_asset_types(
                            cursor,
                            customer_id,
                            chunk["findings"],
                            asset_types,
                        )
                    cursor.execute(
                        """INSERT INTO ingestion_chunks
                           (scan_run_id, chunk_index, start_index, row_count)
                           VALUES (%s, %s, %s, %s)
                           ON CONFLICT (scan_run_id, chunk_index) DO NOTHING
                           RETURNING chunk_index""",
                        (
                            scan_run_id,
                            chunk["chunkIndex"],
                            chunk["startIndex"],
                            len(chunk["findings"]),
                        ),
                    )
                    if not cursor.fetchone():
                        return {
                            "duplicate": True,
                            "receivedFindings": run["received_findings"],
                            "receivedChunks": run["received_chunks"],
                            "status": run["status"],
                        }
                    if run["status"] == "ready":
                        raise MVAError("A finalized scan run cannot accept additional chunks.", 409)
                    cursor.execute(
                        """INSERT INTO finding_observations (
                             scan_run_id, row_index, report_period, report_period_date,
                             finding_key, source_tool, source_tools, source_display,
                             source_vulnerability_id, ip_address, dns_name,
                             vulnerability_name, cve, severity, exploit_available,
                             exploit_signal, epss_score, patch_priority, asset_exposure,
                             vulnerability_finding, summary, description, remediation,
                             kb_links, platform_details, first_discovered, last_observed,
                             vulnerability_age_days, protocol, port, record_count,
                             datacentre, times_detected, vendor_severity_label,
                             vulnerability_status, vulnerability_confidence,
                             exploit_evidence_source, threat, impact, product,
                             asset_criticality, internet_exposed,
                             internet_exposure_known, cisa_kev, namespace, deployment,
                             image, component, fixable, fixable_signal, fixed_in,
                             cvss_score, normalized_payload
                           )
                           SELECT
                             %s::uuid,
                             (item->>'rowIndex')::integer,
                             item->>'reportPeriod',
                             NULLIF(item->>'reportPeriodDate', '')::date,
                             item->>'findingKey',
                             item->>'sourceTool',
                             ARRAY(SELECT jsonb_array_elements_text(item->'sourceTools')),
                             item->>'sourceDisplay',
                             item->>'sourceVulnerabilityId',
                             item->>'ipAddress',
                             item->>'dnsName',
                             item->>'vulnerabilityName',
                             item->>'cve',
                             item->>'severity',
                             (item->>'exploitAvailable')::boolean,
                             item->>'exploitSignal',
                             NULLIF(item->>'epssScore', '')::double precision,
                             item->>'patchPriority',
                             (item->>'assetExposure')::smallint,
                             item->>'vulnerabilityFinding',
                             item->>'summary',
                             item->>'description',
                             item->>'remediation',
                             item->>'kbLinks',
                             item->>'platformDetails',
                             NULLIF(item->>'firstDiscovered', '')::date,
                             NULLIF(item->>'lastObserved', '')::date,
                             NULLIF(item->>'vulnerabilityAgeDays', '')::integer,
                             item->>'protocol',
                             item->>'port',
                             (item->>'recordCount')::integer,
                             item->>'datacentre',
                             (item->>'timesDetected')::integer,
                             item->>'vendorSeverityLabel',
                             item->>'vulnerabilityStatus',
                             item->>'vulnerabilityConfidence',
                             item->>'exploitEvidenceSource',
                             item->>'threat',
                             item->>'impact',
                             item->>'product',
                             item->>'assetCriticality',
                             (item->>'internetExposed')::boolean,
                             (item->>'internetExposureKnown')::boolean,
                             (item->>'cisaKev')::boolean,
                             item->>'namespace',
                             item->>'deployment',
                             item->>'image',
                             item->>'component',
                             (item->>'fixable')::boolean,
                             item->>'fixableSignal',
                             item->>'fixedIn',
                             NULLIF(item->>'cvssScore', '')::double precision,
                             item->'payload'
                           FROM jsonb_array_elements(%s::jsonb) AS item""",
                        (scan_run_id, Jsonb(chunk["findings"])),
                    )
                    chunk_weight = sum(item["recordCount"] for item in chunk["findings"])
                    cursor.execute(
                        """UPDATE scan_runs
                           SET received_findings = received_findings + %s,
                               weighted_findings = weighted_findings + %s,
                               received_chunks = received_chunks + 1,
                               updated_at = now()
                           WHERE id = %s
                           RETURNING received_findings, weighted_findings,
                                     received_chunks, status""",
                        (len(chunk["findings"]), chunk_weight, scan_run_id),
                    )
                    updated = cursor.fetchone()
        return {
            "duplicate": False,
            "receivedFindings": updated["received_findings"],
            "weightedFindings": int(updated["weighted_findings"]),
            "receivedChunks": updated["received_chunks"],
            "status": updated["status"],
        }

    def finalize_scan_run(self, customer_id: str, scan_run_id: str) -> dict:
        finalized = self._one(
            """UPDATE scan_runs
               SET status = 'ready',
                   finalized_at = COALESCE(finalized_at, now()),
                   updated_at = now()
               WHERE id = %s AND customer_id = %s
                 AND received_findings = expected_findings
                 AND received_chunks = expected_chunks
               RETURNING *""",
            (scan_run_id, customer_id),
        )
        if finalized:
            self.sync_observed_assets(customer_id, scan_run_id)
            return self.get_scan_run(customer_id, scan_run_id)
        current = self._one(
            "SELECT * FROM scan_runs WHERE id = %s AND customer_id = %s",
            (scan_run_id, customer_id),
        )
        if not current:
            raise MVAError("Scan run was not found.", 404)
        if current["status"] == "ready":
            return self.get_scan_run(customer_id, scan_run_id)
        raise MVAError(
            "Cannot finalize: received "
            f"{current['received_findings']}/{current['expected_findings']} findings "
            f"and {current['received_chunks']}/{current['expected_chunks']} chunks.",
            409,
        )

    def list_scan_runs(
        self,
        customer_id: str,
        limit: int = 20,
        asset_types: list[str] | None = None,
    ) -> list[dict]:
        asset_types = asset_types or []
        rows = self._all(
            f"""SELECT run.id, run.customer_id, run.customer_name, run.ingestion_key,
                       run.workflow, run.source_tool, run.source_label,
                       run.report_period, run.file_names, run.source_ids,
                       CASE WHEN cardinality(%(asset_types)s::text[]) = 0
                            THEN run.expected_findings ELSE scoped.finding_count END
                            AS expected_findings,
                       CASE WHEN cardinality(%(asset_types)s::text[]) = 0
                            THEN run.received_findings ELSE scoped.finding_count END
                            AS received_findings,
                       CASE WHEN cardinality(%(asset_types)s::text[]) = 0
                            THEN run.weighted_findings ELSE scoped.finding_count END
                            AS weighted_findings,
                       run.expected_chunks, run.received_chunks, run.status,
                       run.dashboard, run.input_summary, run.created_at,
                       run.finalized_at
                FROM scan_runs run
                LEFT JOIN LATERAL (
                  SELECT COALESCE(sum(finding.record_count), 0)::bigint AS finding_count
                  FROM finding_observations finding
                  WHERE finding.scan_run_id = run.id
                    AND {_asset_type_scope_sql("finding")}
                ) scoped ON true
                WHERE run.customer_id = %(customer_id)s
                ORDER BY run.created_at DESC
                LIMIT %(limit)s""",
            {
                "customer_id": customer_id,
                "asset_types": asset_types,
                "limit": limit,
            },
        )
        return [serialize_run(row) for row in rows]

    def get_scan_run(
        self,
        customer_id: str,
        scan_run_id: str,
        asset_types: list[str] | None = None,
    ) -> dict:
        asset_types = asset_types or []
        run = self._one(
            "SELECT * FROM scan_runs WHERE id = %s AND customer_id = %s",
            (scan_run_id, customer_id),
        )
        if not run:
            raise MVAError("Scan run was not found.", 404)
        metrics = self._all(
            f"""SELECT severity, patch_priority,
                       sum(record_count)::bigint AS finding_count
                FROM finding_observations finding
                WHERE finding.scan_run_id = %(scan_run_id)s
                  AND {_asset_type_scope_sql("finding")}
                GROUP BY severity, patch_priority
                ORDER BY patch_priority, severity""",
            {
                "customer_id": customer_id,
                "scan_run_id": scan_run_id,
                "asset_types": asset_types,
            },
        )
        sources = self._all(
            f"""SELECT source_tool, sum(record_count)::bigint AS finding_count
                FROM finding_observations finding
                WHERE finding.scan_run_id = %(scan_run_id)s
                  AND {_asset_type_scope_sql("finding")}
                GROUP BY source_tool ORDER BY source_tool""",
            {
                "customer_id": customer_id,
                "scan_run_id": scan_run_id,
                "asset_types": asset_types,
            },
        )
        scoped_count = sum(int(row["finding_count"]) for row in metrics)
        serialized = serialize_run(run)
        if asset_types:
            serialized.update({
                "expectedFindings": scoped_count,
                "receivedFindings": scoped_count,
                "weightedFindings": scoped_count,
            })
        serialized["metrics"] = [
            {**row, "finding_count": int(row["finding_count"])}
            for row in metrics
        ]
        serialized["sources"] = [
            {**row, "finding_count": int(row["finding_count"])}
            for row in sources
        ]
        return serialized

    def sync_observed_assets(self, customer_id: str, scan_run_id: str) -> None:
        customer = self._one(
            "SELECT asset_scope_mode FROM customers WHERE id = %s",
            (customer_id,),
        )
        if not customer:
            return
        observed_in_scope = customer["asset_scope_mode"] == "observed"
        self._execute(
            """INSERT INTO customer_assets (
                 customer_id, asset_key, ip_address, dns_name, host_name,
                 asset_type, onboarding_tool, platform, criticality,
                 internet_exposed, origin, in_scope, first_seen_at, last_seen_at
               )
               SELECT %s::uuid,
                      lower(COALESCE(NULLIF(trim(ip_address), ''),
                                     NULLIF(trim(dns_name), ''))) AS asset_key,
                      max(ip_address), max(dns_name), max(dns_name),
                      CASE
                        WHEN lower(max(platform_details)) ~
                             '(router|switch|wireless|network|load balancer)'
                          THEN 'Network Device'
                        WHEN lower(max(platform_details)) ~
                             '(firewall|waf|ids|ips|security appliance)'
                          THEN 'Security Appliance'
                        WHEN lower(max(platform_details)) ~
                             '(linux|ubuntu|debian|red hat|rhel|centos|suse|unix)'
                          THEN 'Linux Server'
                        WHEN lower(max(platform_details)) ~ '(windows server)'
                          THEN 'Windows Server'
                        WHEN lower(max(platform_details)) ~
                             '(windows 1[01]|macos|desktop|laptop|workstation)'
                          THEN 'Endpoint'
                        WHEN lower(max(platform_details)) ~
                             '(postgres|mysql|oracle database|sql server|database)'
                          THEN 'Database'
                        WHEN lower(max(platform_details)) ~ '(aws|azure|gcp|cloud)'
                          THEN 'Cloud Asset'
                        WHEN lower(max(platform_details)) ~
                             '(vmware|esxi|hyper-v|virtualization)'
                          THEN 'Virtualization Host'
                        WHEN lower(max(platform_details)) ~
                             '(kubernetes|openshift|container)'
                          THEN 'Container Platform'
                        WHEN lower(max(platform_details)) ~
                             '(scada|plc|industrial|ot device)'
                          THEN 'OT Device'
                        ELSE 'Other'
                      END,
                      CASE
                        WHEN (SELECT source_tool FROM scan_runs WHERE id = %s)
                             IN ('tenable-sc', 'tenable-io', 'qualys',
                                 'crowdstrike', 'openshift', 'mdvm')
                          THEN (SELECT source_tool FROM scan_runs WHERE id = %s)
                        WHEN (SELECT source_tool FROM scan_runs WHERE id = %s)
                             = 'unified'
                          THEN 'multi-tool'
                        ELSE 'other'
                      END,
                      max(platform_details), max(asset_criticality),
                      bool_or(internet_exposed), 'scanner', %s::boolean,
                      COALESCE(min(first_discovered)::timestamptz, now()),
                      COALESCE(max(last_observed)::timestamptz, now())
               FROM finding_observations
               WHERE scan_run_id = %s
                 AND COALESCE(NULLIF(trim(ip_address), ''),
                              NULLIF(trim(dns_name), '')) IS NOT NULL
               GROUP BY lower(COALESCE(NULLIF(trim(ip_address), ''),
                                       NULLIF(trim(dns_name), '')))
               ON CONFLICT (customer_id, asset_key) DO UPDATE SET
                 ip_address = COALESCE(NULLIF(EXCLUDED.ip_address, ''),
                                       customer_assets.ip_address),
                 dns_name = COALESCE(NULLIF(EXCLUDED.dns_name, ''),
                                     customer_assets.dns_name),
                 host_name = COALESCE(NULLIF(customer_assets.host_name, ''),
                                      EXCLUDED.host_name),
                 asset_type = CASE WHEN customer_assets.origin = 'manual'
                                   THEN customer_assets.asset_type
                                   ELSE EXCLUDED.asset_type END,
                 onboarding_tool = CASE
                   WHEN customer_assets.onboarding_tool IN ('manual', 'other')
                     THEN EXCLUDED.onboarding_tool
                   WHEN customer_assets.onboarding_tool = EXCLUDED.onboarding_tool
                     THEN customer_assets.onboarding_tool
                   ELSE 'multi-tool'
                 END,
                 platform = COALESCE(NULLIF(customer_assets.platform, ''),
                                     EXCLUDED.platform),
                 criticality = COALESCE(NULLIF(customer_assets.criticality, ''),
                                        EXCLUDED.criticality),
                 internet_exposed = COALESCE(customer_assets.internet_exposed,
                                             EXCLUDED.internet_exposed),
                 in_scope = customer_assets.in_scope OR %s::boolean,
                 last_seen_at = GREATEST(customer_assets.last_seen_at,
                                         EXCLUDED.last_seen_at),
                 updated_at = now()""",
            (
                customer_id,
                scan_run_id,
                scan_run_id,
                scan_run_id,
                observed_in_scope,
                scan_run_id,
                observed_in_scope,
            ),
        )

    def get_customer_scan_asset_coverage(
        self,
        customer_id: str,
        asset_types: list[str] | None = None,
    ) -> dict:
        asset_types = asset_types or []
        latest_run = self._one(
            f"""SELECT run.*
                FROM scan_runs run
                WHERE run.customer_id = %(customer_id)s
                  AND run.status = 'ready'
                  AND EXISTS (
                    SELECT 1 FROM finding_observations finding
                    WHERE finding.scan_run_id = run.id
                      AND {_asset_type_scope_sql("finding")}
                  )
                ORDER BY COALESCE(run.finalized_at, run.created_at) DESC,
                         run.created_at DESC
                LIMIT 1""",
            {"customer_id": customer_id, "asset_types": asset_types},
        )
        if not latest_run:
            return {
                "available": False,
                "runId": None,
                "reportPeriod": "",
                "sourceLabel": "",
                "observedScanIdentities": 0,
                "matchedInventoryAssets": 0,
                "unmatchedScanIdentities": 0,
                "ambiguousScanIdentities": 0,
                "assetIds": [],
            }
        period = self._one(
            f"""SELECT max(finding.report_period_date) AS report_period_date
                FROM finding_observations finding
                WHERE finding.scan_run_id = %(scan_run_id)s
                  AND {_asset_type_scope_sql("finding")}""",
            {
                "customer_id": customer_id,
                "asset_types": asset_types,
                "scan_run_id": latest_run["id"],
            },
        )
        report_date = period["report_period_date"] if period else None
        rows = self._all(
            """WITH observations AS (
                 SELECT DISTINCT
                        lower(NULLIF(trim(finding.ip_address), '')) AS ip_address,
                        lower(NULLIF(trim(finding.dns_name), '')) AS dns_name
                 FROM finding_observations finding
                 WHERE finding.scan_run_id = %(scan_run_id)s
                   AND (
                     %(report_date)s::date IS NULL
                     OR finding.report_period_date = %(report_date)s::date
                   )
                   AND """ + _asset_type_scope_sql("finding") + """
                   AND COALESCE(
                     NULLIF(trim(finding.ip_address), ''),
                     NULLIF(trim(finding.dns_name), '')
                   ) IS NOT NULL
               ), candidate_matches AS (
                 SELECT observation.ip_address, observation.dns_name,
                        COALESCE(
                          array_agg(DISTINCT asset.id)
                            FILTER (WHERE asset.id IS NOT NULL),
                          ARRAY[]::uuid[]
                        ) AS asset_ids
                 FROM observations observation
                 LEFT JOIN customer_assets asset
                   ON asset.customer_id = %(customer_id)s
                  AND asset.in_scope
                  AND (
                    cardinality(%(asset_types)s::text[]) = 0
                    OR asset.asset_type = ANY(%(asset_types)s::text[])
                  )
                  AND (
                    asset.asset_key IN (
                      observation.ip_address, observation.dns_name
                    )
                    OR lower(NULLIF(trim(asset.ip_address), '')) IN (
                      observation.ip_address, observation.dns_name
                    )
                    OR lower(NULLIF(trim(asset.dns_name), '')) IN (
                      observation.ip_address, observation.dns_name
                    )
                    OR EXISTS (
                      SELECT 1 FROM customer_asset_aliases alias
                      WHERE alias.customer_id = %(customer_id)s
                        AND alias.asset_id = asset.id
                        AND alias.alias IN (
                          observation.ip_address, observation.dns_name
                        )
                    )
                  )
                 GROUP BY observation.ip_address, observation.dns_name
               )
               SELECT ip_address, dns_name, asset_ids FROM candidate_matches""",
            {
                "customer_id": customer_id,
                "asset_types": asset_types,
                "scan_run_id": latest_run["id"],
                "report_date": report_date,
            },
        )
        matched_ids: set = set()
        unmatched = 0
        ambiguous = 0
        for row in rows:
            ids = row["asset_ids"] or []
            if len(ids) == 1:
                matched_ids.add(ids[0])
            elif len(ids) > 1:
                ambiguous += 1
            else:
                unmatched += 1
        return {
            "available": True,
            "runId": latest_run["id"],
            "workflow": latest_run["workflow"],
            "sourceTool": latest_run["source_tool"],
            "sourceLabel": latest_run["source_label"],
            "reportPeriod": _calendar_date(report_date) or latest_run["report_period"],
            "finalizedAt": latest_run["finalized_at"],
            "observedScanIdentities": len(rows),
            "matchedInventoryAssets": len(matched_ids),
            "unmatchedScanIdentities": unmatched,
            "ambiguousScanIdentities": ambiguous,
            "assetIds": list(matched_ids),
        }

    def get_customer_dashboard(
        self,
        customer_id: str,
        asset_types: list[str] | None = None,
        team_id: str | None = None,
        asset_id: str | None = None,
    ) -> dict:
        asset_types = asset_types or []
        customer_row = self._one("SELECT * FROM customers WHERE id = %s", (customer_id,))
        if not customer_row:
            raise MVAError("Customer was not found.", 404)
        customer = serialize_customer(customer_row)
        scope = {
            "customer_id": customer_id,
            "asset_types": asset_types,
            "team_id": team_id,
            "asset_id": asset_id,
        }
        inventory_row = self._one(
            """WITH typed AS (
                 SELECT asset_type, count(*)::integer AS total,
                        count(*) FILTER (WHERE in_scope)::integer AS in_scope,
                        count(*) FILTER (WHERE origin = 'manual')::integer AS manual,
                        count(*) FILTER (WHERE origin = 'scanner')::integer AS discovered
                 FROM customer_assets
                 WHERE customer_id = %(customer_id)s
                   AND (
                     cardinality(%(asset_types)s::text[]) = 0
                     OR asset_type = ANY(%(asset_types)s::text[])
                   )
                   AND (%(team_id)s::uuid IS NULL OR team_id = %(team_id)s::uuid)
                   AND (%(asset_id)s::uuid IS NULL OR id = %(asset_id)s::uuid)
                 GROUP BY asset_type
               )
               SELECT COALESCE(sum(total), 0)::integer AS total_assets,
                      COALESCE(sum(in_scope), 0)::integer AS in_scope_assets,
                      COALESCE(sum(manual), 0)::integer AS manual_assets,
                      COALESCE(sum(discovered), 0)::integer AS discovered_assets,
                      COALESCE(jsonb_object_agg(asset_type, total),
                               '{}'::jsonb) AS asset_types
               FROM typed""",
            scope,
        )
        inventory = _serialize_inventory(inventory_row or {})
        latest_run = self._one(
            """SELECT * FROM scan_runs
               WHERE customer_id = %s AND status = 'ready'
               ORDER BY finalized_at DESC NULLS LAST, created_at DESC
               LIMIT 1""",
            (customer_id,),
        )
        if not latest_run:
            return _empty_dashboard(customer, inventory)
        periods = self._all(
            """SELECT report_period_date, min(report_period) AS report_period
               FROM finding_observations
               WHERE scan_run_id = %s
               GROUP BY report_period_date
               ORDER BY report_period_date DESC NULLS LAST""",
            (latest_run["id"],),
        )
        dated_periods = [row for row in periods if row["report_period_date"]]
        current_period = (dated_periods or periods or [{
            "report_period_date": None,
            "report_period": latest_run["report_period"],
        }])[0]
        current_date = current_period["report_period_date"]
        previous_run_id = latest_run["id"]
        previous_period = dated_periods[1] if len(dated_periods) > 1 else None
        if not previous_period:
            previous = self._one(
                """SELECT run.id, period.report_period_date, period.report_period
                   FROM scan_runs run
                   JOIN LATERAL (
                     SELECT report_period_date, min(report_period) AS report_period
                     FROM finding_observations
                     WHERE scan_run_id = run.id
                       AND (
                         %(current_date)s::date IS NULL
                         OR report_period_date < %(current_date)s::date
                       )
                     GROUP BY report_period_date
                     ORDER BY report_period_date DESC NULLS LAST
                     LIMIT 1
                   ) period ON true
                   WHERE run.customer_id = %(customer_id)s
                     AND run.status = 'ready'
                     AND run.id <> %(latest_run_id)s
                     AND run.source_tool = %(source_tool)s
                   ORDER BY period.report_period_date DESC NULLS LAST,
                            run.finalized_at DESC NULLS LAST,
                            run.created_at DESC
                   LIMIT 1""",
                {
                    "customer_id": customer_id,
                    "current_date": current_date,
                    "latest_run_id": latest_run["id"],
                    "source_tool": latest_run["source_tool"],
                },
            )
            if previous:
                previous_run_id = previous["id"]
                previous_period = previous
        if not previous_period:
            previous_run_id = None
        params = {
            **scope,
            "latest_run_id": latest_run["id"],
            "current_date": current_date,
            "previous_run_id": previous_run_id,
            "previous_date": previous_period["report_period_date"] if previous_period else None,
        }
        current_where = (
            "finding.scan_run_id = %(latest_run_id)s "
            "AND (%(current_date)s::date IS NULL "
            "OR finding.report_period_date = %(current_date)s::date) "
            f"AND {_inventory_scope_sql('finding')} "
            f"AND {_asset_type_scope_sql('finding')} "
            f"AND {_team_scope_sql('finding')} "
            f"AND {_asset_scope_sql('finding')}"
        )
        metric_row = self._one(
            f"""SELECT
                  COALESCE(sum(finding.record_count), 0)::bigint AS total_open,
                  count(DISTINCT lower(COALESCE(
                    NULLIF(finding.dns_name, ''),
                    NULLIF(finding.ip_address, '')
                  )))::integer AS affected_assets,
                  COALESCE(sum(finding.record_count) FILTER (
                    WHERE finding.patch_priority IN ('P1', 'P2')
                  ), 0)::bigint AS immediate_patch,
                  COALESCE(sum(finding.record_count) FILTER (
                    WHERE finding.exploit_available
                  ), 0)::bigint AS exploitable
                FROM finding_observations finding
                WHERE {current_where}""",
            params,
        )
        distributions = self._all(
            f"""SELECT 'severity' AS dimension, finding.severity AS label,
                       sum(finding.record_count)::bigint AS count
                FROM finding_observations finding
                WHERE {current_where}
                GROUP BY finding.severity
                UNION ALL
                SELECT 'priority', finding.patch_priority,
                       sum(finding.record_count)::bigint
                FROM finding_observations finding
                WHERE {current_where}
                GROUP BY finding.patch_priority
                UNION ALL
                SELECT 'source', finding.source_tool,
                       sum(finding.record_count)::bigint
                FROM finding_observations finding
                WHERE {current_where}
                GROUP BY finding.source_tool""",
            params,
        )
        lifecycle = self._one(
            f"""WITH current_set AS (
                  SELECT finding.finding_key,
                         sum(finding.record_count)::bigint AS count
                  FROM finding_observations finding
                  WHERE finding.scan_run_id = %(latest_run_id)s
                    AND (
                      %(current_date)s::date IS NULL
                      OR finding.report_period_date = %(current_date)s::date
                    )
                    AND {_inventory_scope_sql("finding")}
                    AND {_asset_type_scope_sql("finding")}
                    AND {_team_scope_sql("finding")}
                    AND {_asset_scope_sql("finding")}
                  GROUP BY finding.finding_key
                ), previous_set AS (
                  SELECT finding.finding_key,
                         sum(finding.record_count)::bigint AS count
                  FROM finding_observations finding
                  WHERE %(previous_run_id)s::uuid IS NOT NULL
                    AND finding.scan_run_id = %(previous_run_id)s
                    AND (
                      %(previous_date)s::date IS NULL
                      OR finding.report_period_date = %(previous_date)s::date
                    )
                    AND {_inventory_scope_sql("finding")}
                    AND {_asset_type_scope_sql("finding")}
                    AND {_team_scope_sql("finding")}
                    AND {_asset_scope_sql("finding")}
                  GROUP BY finding.finding_key
                )
                SELECT
                  CASE WHEN %(previous_run_id)s::uuid IS NULL THEN 0
                       ELSE COALESCE(sum(current_set.count)
                         FILTER (WHERE previous_set.finding_key IS NULL), 0)
                  END::bigint AS new_count,
                  CASE WHEN %(previous_run_id)s::uuid IS NULL THEN 0
                       ELSE COALESCE(sum(previous_set.count)
                         FILTER (WHERE current_set.finding_key IS NULL), 0)
                  END::bigint AS fixed_count,
                  CASE WHEN %(previous_run_id)s::uuid IS NULL THEN 0
                       ELSE COALESCE(sum(current_set.count)
                         FILTER (WHERE previous_set.finding_key IS NOT NULL), 0)
                  END::bigint AS repeated_count
                FROM current_set
                FULL OUTER JOIN previous_set USING (finding_key)""",
            params,
        )
        age_rows = self._all(
            f"""SELECT finding.patch_priority,
                       CASE
                         WHEN COALESCE(finding.vulnerability_age_days, 0) <= 7
                           THEN '0-7 days'
                         WHEN finding.vulnerability_age_days <= 30
                           THEN '8-30 days'
                         WHEN finding.vulnerability_age_days <= 60
                           THEN '31-60 days'
                         WHEN finding.vulnerability_age_days <= 180
                           THEN '61-180 days'
                         ELSE 'Over 180 days'
                       END AS age_bucket,
                       sum(finding.record_count)::bigint AS count
                FROM finding_observations finding
                WHERE {current_where}
                GROUP BY finding.patch_priority, age_bucket""",
            params,
        )
        top_assets = self._all(
            f"""SELECT COALESCE(
                         NULLIF(finding.dns_name, ''),
                         NULLIF(finding.ip_address, ''),
                         'Unknown asset'
                       ) AS asset,
                       max(finding.ip_address) AS ip_address,
                       sum(finding.record_count)::bigint AS total,
                       COALESCE(sum(finding.record_count) FILTER (
                         WHERE finding.patch_priority = 'P1'
                       ), 0)::bigint AS p1,
                       COALESCE(sum(finding.record_count) FILTER (
                         WHERE finding.patch_priority = 'P2'
                       ), 0)::bigint AS p2
                FROM finding_observations finding
                WHERE {current_where}
                GROUP BY COALESCE(
                  NULLIF(finding.dns_name, ''),
                  NULLIF(finding.ip_address, ''),
                  'Unknown asset'
                )
                ORDER BY total DESC, asset
                LIMIT 10""",
            params,
        )
        trend = self._all(
            f"""WITH candidate_periods AS (
                  SELECT run.id AS scan_run_id,
                         finding.report_period_date,
                         min(finding.report_period) AS report_period,
                         run.finalized_at,
                         row_number() OVER (
                           PARTITION BY finding.report_period_date
                           ORDER BY run.finalized_at DESC NULLS LAST,
                                    run.created_at DESC
                         ) AS rank
                  FROM scan_runs run
                  JOIN finding_observations finding
                    ON finding.scan_run_id = run.id
                  WHERE run.customer_id = %(customer_id)s
                    AND run.status = 'ready'
                    AND finding.report_period_date IS NOT NULL
                  GROUP BY run.id, finding.report_period_date,
                           run.finalized_at, run.created_at
                ), selected_periods AS (
                  SELECT * FROM candidate_periods
                  WHERE rank = 1
                  ORDER BY report_period_date DESC
                  LIMIT 6
                )
                SELECT selected.report_period_date, selected.report_period,
                       sum(finding.record_count)::bigint AS total_open
                FROM selected_periods selected
                JOIN finding_observations finding
                  ON finding.scan_run_id = selected.scan_run_id
                 AND finding.report_period_date = selected.report_period_date
                WHERE {_inventory_scope_sql("finding")}
                  AND {_asset_type_scope_sql("finding")}
                  AND {_team_scope_sql("finding")}
                  AND {_asset_scope_sql("finding")}
                GROUP BY selected.report_period_date, selected.report_period
                ORDER BY selected.report_period_date""",
            params,
        )
        unfiltered = self._one(
            f"""SELECT COALESCE(sum(record_count), 0)::bigint AS count
                FROM finding_observations finding
                WHERE finding.scan_run_id = %(latest_run_id)s
                  AND (
                    %(current_date)s::date IS NULL
                    OR finding.report_period_date = %(current_date)s::date
                  )
                  AND {_asset_type_scope_sql("finding")}
                  AND {_team_scope_sql("finding")}
                  AND {_asset_scope_sql("finding")}""",
            params,
        )
        team_breakdown = self._all(
            f"""WITH team_assets AS (
                  SELECT team_id, count(*)::integer AS asset_count,
                         count(*) FILTER (WHERE in_scope)::integer
                           AS in_scope_asset_count
                  FROM customer_assets
                  WHERE customer_id = %(customer_id)s
                    AND team_id IS NOT NULL
                    AND (
                      cardinality(%(asset_types)s::text[]) = 0
                      OR asset_type = ANY(%(asset_types)s::text[])
                    )
                    AND (
                      %(asset_id)s::uuid IS NULL
                      OR id = %(asset_id)s::uuid
                    )
                  GROUP BY team_id
                ), finding_owners AS (
                  SELECT owner.team_id,
                         sum(finding.record_count)::bigint AS total_open,
                         COALESCE(sum(finding.record_count) FILTER (
                           WHERE finding.patch_priority = 'P1'
                         ), 0)::bigint AS p1,
                         COALESCE(sum(finding.record_count) FILTER (
                           WHERE finding.patch_priority = 'P2'
                         ), 0)::bigint AS p2
                  FROM finding_observations finding
                  JOIN LATERAL (
                    SELECT owned_asset.team_id
                    FROM customer_assets owned_asset
                    WHERE owned_asset.customer_id = %(customer_id)s
                      AND owned_asset.in_scope
                      AND owned_asset.team_id IS NOT NULL
                      AND (
                        cardinality(%(asset_types)s::text[]) = 0
                        OR owned_asset.asset_type =
                           ANY(%(asset_types)s::text[])
                      )
                      AND (
                        %(asset_id)s::uuid IS NULL
                        OR owned_asset.id = %(asset_id)s::uuid
                      )
                      AND {_finding_asset_match_sql("finding", "owned_asset")}
                    ORDER BY owned_asset.origin = 'manual' DESC,
                             owned_asset.updated_at DESC
                    LIMIT 1
                  ) owner ON true
                  WHERE finding.scan_run_id = %(latest_run_id)s
                    AND (
                      %(current_date)s::date IS NULL
                      OR finding.report_period_date = %(current_date)s::date
                    )
                    AND {_inventory_scope_sql("finding")}
                  GROUP BY owner.team_id
                )
                SELECT team.id, team.name, team.code,
                       COALESCE(team_assets.asset_count, 0)::integer
                         AS asset_count,
                       COALESCE(team_assets.in_scope_asset_count, 0)::integer
                         AS in_scope_asset_count,
                       COALESCE(finding_owners.total_open, 0)::bigint
                         AS total_open,
                       COALESCE(finding_owners.p1, 0)::bigint AS p1,
                       COALESCE(finding_owners.p2, 0)::bigint AS p2
                FROM customer_teams team
                LEFT JOIN team_assets ON team_assets.team_id = team.id
                LEFT JOIN finding_owners ON finding_owners.team_id = team.id
                WHERE team.customer_id = %(customer_id)s
                  AND (
                    %(team_id)s::uuid IS NULL
                    OR team.id = %(team_id)s::uuid
                  )
                ORDER BY total_open DESC, team.name""",
            params,
        )

        def distribution(dimension: str) -> dict:
            return {
                row["label"]: int(row["count"])
                for row in distributions
                if row["dimension"] == dimension
            }

        metric_row = metric_row or {}
        lifecycle = lifecycle or {}
        total_open = int(metric_row.get("total_open") or 0)
        return {
            "customer": customer,
            "latestRun": serialize_run(latest_run),
            "currentPeriod": current_period["report_period"],
            "previousPeriod": (
                previous_period["report_period"] if previous_period else None
            ),
            "comparisonAvailable": bool(previous_run_id),
            "metrics": {
                "totalOpen": total_open,
                "affectedAssets": int(metric_row.get("affected_assets") or 0),
                "immediatePatch": int(metric_row.get("immediate_patch") or 0),
                "exploitable": int(metric_row.get("exploitable") or 0),
                "newFindings": int(lifecycle.get("new_count") or 0),
                "fixedFindings": int(lifecycle.get("fixed_count") or 0),
                "repeatedFindings": int(lifecycle.get("repeated_count") or 0),
                "excludedByScope": max(
                    0,
                    int((unfiltered or {}).get("count") or 0) - total_open,
                ),
            },
            "severity": distribution("severity"),
            "priority": distribution("priority"),
            "sources": distribution("source"),
            "ageByPriority": [
                {
                    "priority": row["patch_priority"],
                    "bucket": row["age_bucket"],
                    "count": int(row["count"]),
                }
                for row in age_rows
            ],
            "topAssets": [
                {
                    "asset": row["asset"],
                    "ipAddress": row["ip_address"],
                    "total": int(row["total"]),
                    "p1": int(row["p1"]),
                    "p2": int(row["p2"]),
                }
                for row in top_assets
            ],
            "teamBreakdown": [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "code": row["code"],
                    "assetCount": int(row["asset_count"]),
                    "inScopeAssetCount": int(row["in_scope_asset_count"]),
                    "totalOpen": int(row["total_open"]),
                    "p1": int(row["p1"]),
                    "p2": int(row["p2"]),
                }
                for row in team_breakdown
            ],
            "selectedTeamId": team_id,
            "selectedAssetId": asset_id,
            "trend": [
                {
                    "period": row["report_period"],
                    "date": _calendar_date(row["report_period_date"]),
                    "totalOpen": int(row["total_open"]),
                }
                for row in trend
            ],
            "inventory": inventory,
            "recentRuns": self.list_scan_runs(customer_id, 6, asset_types),
        }

    def get_customer_finding_export(
        self,
        customer_id: str,
        asset_types: list[str] | None = None,
        team_id: str | None = None,
        asset_id: str | None = None,
    ) -> dict:
        asset_types = asset_types or []
        customer_row = self._one("SELECT * FROM customers WHERE id = %s", (customer_id,))
        if not customer_row:
            raise MVAError("Customer was not found.", 404)
        customer = serialize_customer(customer_row)
        latest_run = self._one(
            """SELECT * FROM scan_runs
               WHERE customer_id = %s AND status = 'ready'
               ORDER BY finalized_at DESC NULLS LAST, created_at DESC
               LIMIT 1""",
            (customer_id,),
        )
        if not latest_run:
            return {"customer": customer, "reportPeriod": "current", "rows": []}
        period = self._one(
            """SELECT report_period_date, min(report_period) AS report_period
               FROM finding_observations
               WHERE scan_run_id = %s
               GROUP BY report_period_date
               ORDER BY report_period_date DESC NULLS LAST
               LIMIT 1""",
            (latest_run["id"],),
        ) or {
            "report_period_date": None,
            "report_period": latest_run["report_period"],
        }
        params = {
            "customer_id": customer_id,
            "asset_types": asset_types,
            "team_id": team_id,
            "asset_id": asset_id,
            "scan_run_id": latest_run["id"],
            "report_date": period["report_period_date"],
        }
        rows = self._all(
            f"""SELECT finding.ip_address, finding.dns_name,
                       COALESCE(owner.team_name, 'Unassigned') AS asset_owner,
                       finding.vulnerability_name, finding.cve, finding.severity,
                       finding.exploit_available, finding.patch_priority,
                       finding.asset_exposure, finding.vulnerability_finding,
                       finding.summary, finding.description, finding.remediation,
                       finding.kb_links, finding.platform_details,
                       finding.namespace, finding.deployment, finding.image,
                       finding.component, finding.fixable, finding.fixed_in,
                       finding.cvss_score, finding.first_discovered,
                       finding.last_observed
                FROM finding_observations finding
                LEFT JOIN LATERAL (
                  SELECT team.name AS team_name
                  FROM customer_assets owned_asset
                  LEFT JOIN customer_teams team
                    ON team.id = owned_asset.team_id
                   AND team.customer_id = owned_asset.customer_id
                  WHERE owned_asset.customer_id = %(customer_id)s
                    AND {_finding_asset_match_sql("finding", "owned_asset")}
                  ORDER BY owned_asset.origin = 'manual' DESC,
                           owned_asset.updated_at DESC
                  LIMIT 1
                ) owner ON true
                WHERE finding.scan_run_id = %(scan_run_id)s
                  AND (
                    %(report_date)s::date IS NULL
                    OR finding.report_period_date = %(report_date)s::date
                  )
                  AND {_inventory_scope_sql("finding")}
                  AND {_asset_type_scope_sql("finding")}
                  AND {_team_scope_sql("finding")}
                  AND {_asset_scope_sql("finding")}
                ORDER BY
                  CASE finding.patch_priority
                    WHEN 'P1' THEN 1 WHEN 'P2' THEN 2
                    WHEN 'P3' THEN 3 ELSE 4
                  END,
                  CASE finding.severity
                    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5
                  END,
                  finding.ip_address, finding.dns_name,
                  finding.vulnerability_name, finding.row_index""",
            params,
        )
        return {
            "customer": customer,
            "reportPeriod": period["report_period"] or latest_run["report_period"],
            "rows": [
                {
                    "ipAddress": row["ip_address"],
                    "dnsName": row["dns_name"],
                    "assetOwner": row["asset_owner"],
                    "vulnerabilityName": row["vulnerability_name"],
                    "cve": row["cve"],
                    "severity": row["severity"],
                    "exploitAvailable": row["exploit_available"],
                    "patchPriority": row["patch_priority"],
                    "assetExposure": int(row["asset_exposure"] or 0),
                    "vulnerabilityFinding": row["vulnerability_finding"],
                    "summary": row["summary"],
                    "description": row["description"],
                    "remediation": row["remediation"],
                    "kbLinks": row["kb_links"],
                    "platformDetails": row["platform_details"],
                    "namespace": row["namespace"],
                    "deployment": row["deployment"],
                    "image": row["image"],
                    "component": row["component"],
                    "fixable": row["fixable"],
                    "fixedIn": row["fixed_in"],
                    "cvssScore": (
                        float(row["cvss_score"])
                        if row["cvss_score"] is not None
                        else None
                    ),
                    "firstDiscovered": _calendar_date(row["first_discovered"]),
                    "lastObserved": _calendar_date(row["last_observed"]),
                }
                for row in rows
            ],
        }

    def create_threat_intel_import(
        self,
        customer_id: str,
        created_by,
        payload: dict,
    ) -> dict:
        import_id = str(uuid4())
        inserted = self._one(
            """INSERT INTO threat_intel_imports (
                 id, customer_id, created_by, ingestion_key, source_label,
                 file_names, expected_records
               ) VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (customer_id, ingestion_key) DO NOTHING
               RETURNING *""",
            (
                import_id,
                customer_id,
                created_by,
                payload["ingestionKey"],
                payload["sourceLabel"],
                payload["fileNames"],
                payload["expectedRecords"],
            ),
        )
        if inserted:
            return {**serialize_threat_import(inserted), "existing": False}
        existing = self._one(
            """SELECT * FROM threat_intel_imports
               WHERE customer_id = %s AND ingestion_key = %s""",
            (customer_id, payload["ingestionKey"]),
        )
        return {**serialize_threat_import(existing), "existing": True}

    def ingest_threat_intel_chunk(
        self,
        customer_id: str,
        import_id: str,
        payload: dict,
    ) -> dict:
        with self.database.pool.connection() as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        """SELECT * FROM threat_intel_imports
                           WHERE id = %s AND customer_id = %s FOR UPDATE""",
                        (import_id, customer_id),
                    )
                    imported = cursor.fetchone()
                    if not imported:
                        raise MVAError("Threat-intelligence import was not found.", 404)
                    if imported["status"] == "ready":
                        raise MVAError(
                            "A finalized threat-intelligence import cannot accept records.",
                            409,
                        )
                    chunk = normalize_threat_chunk(payload, imported["expected_records"])
                    cursor.execute(
                        """INSERT INTO threat_intel_records (
                             import_id, customer_id, row_index, cve,
                             vulnerability_name, source_tool,
                             source_vulnerability_id, ip_address, dns_name,
                             severity, patch_priority, exploit_available,
                             vulnerability_confidence, exploit_evidence,
                             description, remediation, kb_links, product,
                             platform_details, namespace, deployment, image,
                             component, fixable, fixed_in, cvss_score,
                             first_observed, last_observed, normalized_payload
                           )
                           SELECT %s::uuid, %s::uuid,
                                  (item->>'rowIndex')::integer,
                                  item->>'cve', item->>'vulnerabilityName',
                                  item->>'sourceTool',
                                  item->>'sourceVulnerabilityId',
                                  item->>'ipAddress', item->>'dnsName',
                                  item->>'severity', item->>'patchPriority',
                                  (item->>'exploitAvailable')::boolean,
                                  item->>'vulnerabilityConfidence',
                                  item->>'exploitEvidence',
                                  item->>'description', item->>'remediation',
                                  item->>'kbLinks', item->>'product',
                                  item->>'platformDetails', item->>'namespace',
                                  item->>'deployment', item->>'image',
                                  item->>'component',
                                  (item->>'fixable')::boolean,
                                  item->>'fixedIn',
                                  NULLIF(item->>'cvssScore', '')::double precision,
                                  NULLIF(item->>'firstObserved', '')::date,
                                  NULLIF(item->>'lastObserved', '')::date,
                                  item->'payload'
                           FROM jsonb_array_elements(%s::jsonb) AS item
                           ON CONFLICT (import_id, row_index) DO NOTHING
                           RETURNING row_index""",
                        (import_id, customer_id, Jsonb(chunk["records"])),
                    )
                    inserted_count = len(cursor.fetchall())
                    cursor.execute(
                        """UPDATE threat_intel_imports
                           SET received_records = received_records + %s,
                               updated_at = now()
                           WHERE id = %s
                           RETURNING *""",
                        (inserted_count, import_id),
                    )
                    updated = cursor.fetchone()
        return {
            "inserted": inserted_count,
            "import": serialize_threat_import(updated),
        }

    def finalize_threat_intel_import(
        self,
        customer_id: str,
        import_id: str,
    ) -> dict:
        finalized = self._one(
            """UPDATE threat_intel_imports
               SET status = 'ready',
                   finalized_at = COALESCE(finalized_at, now()),
                   updated_at = now()
               WHERE id = %s AND customer_id = %s
                 AND received_records = expected_records
               RETURNING *""",
            (import_id, customer_id),
        )
        if finalized:
            return serialize_threat_import(finalized)
        current = self._one(
            "SELECT * FROM threat_intel_imports WHERE id = %s AND customer_id = %s",
            (import_id, customer_id),
        )
        if not current:
            raise MVAError("Threat-intelligence import was not found.", 404)
        if current["status"] == "ready":
            return serialize_threat_import(current)
        raise MVAError(
            "Cannot finalize threat intelligence: received "
            f"{current['received_records']}/{current['expected_records']} records.",
            409,
        )

    def search_threat_intel(
        self,
        customer_id: str,
        query: str = "",
        limit: int = 100,
    ) -> list[dict]:
        needle = str(query or "").strip().lower()
        rows = self._all(
            """SELECT record.*, imported.source_label, imported.file_names,
                      imported.finalized_at
               FROM threat_intel_records record
               JOIN threat_intel_imports imported ON imported.id = record.import_id
               WHERE record.customer_id = %s
                 AND imported.status = 'ready'
                 AND (
                   %s = ''
                   OR lower(record.cve) LIKE %s
                   OR lower(record.vulnerability_name) LIKE %s
                   OR lower(record.source_vulnerability_id) LIKE %s
                   OR lower(record.product) LIKE %s
                   OR lower(record.component) LIKE %s
                   OR lower(record.image) LIKE %s
                 )
               ORDER BY
                 CASE record.patch_priority
                   WHEN 'P1' THEN 1 WHEN 'P2' THEN 2
                   WHEN 'P3' THEN 3 ELSE 4
                 END,
                 CASE record.severity
                   WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                   WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5
                 END,
                 record.last_observed DESC NULLS LAST,
                 record.vulnerability_name
               LIMIT %s""",
            (
                customer_id,
                needle,
                *([f"%{needle}%"] * 6),
                max(1, min(500, int(limit or 100))),
            ),
        )
        return [serialize_threat_record(row) for row in rows]

    def save_threat_intel_enrichment(
        self,
        actor_user_id,
        customer_id: str,
        payload: dict,
    ) -> dict:
        row = self._one(
            """INSERT INTO threat_intel_enrichments (
                 customer_id, created_by, query, model, evidence_count,
                 response_text
               ) VALUES (%s, %s, %s, %s, %s, %s)
               RETURNING id, created_at""",
            (
                customer_id,
                actor_user_id,
                payload["query"],
                payload["model"],
                payload["evidenceCount"],
                payload["responseText"],
            ),
        )
        return {"id": row["id"], "createdAt": row["created_at"]}

    @staticmethod
    def _assert_findings_match_asset_types(
        cursor,
        customer_id: str,
        findings: list[dict],
        asset_types: list[str],
    ) -> None:
        cursor.execute(
            """SELECT item->>'findingKey' AS finding_key,
                      COALESCE(
                        NULLIF(item->>'dnsName', ''),
                        NULLIF(item->>'ipAddress', ''),
                        'Unknown asset'
                      ) AS asset
               FROM jsonb_array_elements(%s::jsonb) item
               WHERE NOT EXISTS (
                 SELECT 1 FROM customer_assets allowed_asset
                 WHERE allowed_asset.customer_id = %s
                   AND allowed_asset.in_scope
                   AND allowed_asset.asset_type = ANY(%s::text[])
                   AND (
                     allowed_asset.asset_key IN (
                       lower(NULLIF(item->>'ipAddress', '')),
                       lower(NULLIF(item->>'dnsName', ''))
                     )
                     OR lower(NULLIF(allowed_asset.ip_address, '')) IN (
                       lower(NULLIF(item->>'ipAddress', '')),
                       lower(NULLIF(item->>'dnsName', ''))
                     )
                     OR lower(NULLIF(allowed_asset.dns_name, '')) IN (
                       lower(NULLIF(item->>'ipAddress', '')),
                       lower(NULLIF(item->>'dnsName', ''))
                     )
                     OR EXISTS (
                       SELECT 1 FROM customer_asset_aliases allowed_alias
                       WHERE allowed_alias.customer_id = %s
                         AND allowed_alias.asset_id = allowed_asset.id
                         AND allowed_alias.alias IN (
                           lower(NULLIF(item->>'ipAddress', '')),
                           lower(NULLIF(item->>'dnsName', ''))
                         )
                     )
                   )
               )
               LIMIT 1""",
            (Jsonb(findings), customer_id, asset_types, customer_id),
        )
        violation = cursor.fetchone()
        if violation:
            raise MVAError(
                f"Finding '{violation['finding_key']}' belongs to "
                f"{violation['asset']}, which is outside this account's "
                f"{', '.join(asset_types)} asset scope.",
                403,
            )

    def audit(
        self,
        actor_user_id,
        customer_id,
        event_type: str,
        event_data: dict | None = None,
        ip_address: str = "",
    ) -> None:
        self._execute(
            """INSERT INTO audit_events
               (actor_user_id, customer_id, event_type, event_data, ip_address)
               VALUES (%s, %s, %s, %s, %s)""",
            (
                actor_user_id,
                customer_id,
                event_type,
                Jsonb(json.loads(json.dumps(event_data or {}, default=str))),
                ip_address[:200],
            ),
        )

    def _one(self, query: str, params: tuple | dict | None = None) -> dict | None:
        with self.database.pool.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()
            connection.commit()
            return row

    def _all(self, query: str, params: tuple | dict | None = None) -> list[dict]:
        with self.database.pool.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                rows = cursor.fetchall()
            connection.commit()
            return rows

    def _execute(self, query: str, params: tuple | dict | None = None) -> int:
        with self.database.pool.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                count = cursor.rowcount
            connection.commit()
            return count


def serialize_user(row: dict) -> dict:
    return {
        "id": row["id"],
        "email": row["email"],
        "fullName": row["full_name"],
        "globalRole": row["global_role"],
        "status": row["status"],
        "createdAt": row.get("created_at"),
        "lastLoginAt": row.get("last_login_at"),
    }


def serialize_customer(row: dict) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "slug": row["slug"],
        "status": row["status"],
        "assetScopeMode": row["asset_scope_mode"],
        "notes": row.get("notes") or "",
        "membershipRole": row.get("membership_role"),
        "assetTypeScope": row.get("asset_type_scope") or [],
        "assetCount": int(row.get("asset_count") or 0),
        "scanCount": int(row.get("scan_count") or 0),
        "createdAt": row.get("created_at"),
        "updatedAt": row.get("updated_at"),
    }


def serialize_team(row: dict) -> dict:
    return {
        "id": row["id"],
        "customerId": row["customer_id"],
        "name": row["name"],
        "code": row["code"],
        "description": row.get("description") or "",
        "assetCount": int(row.get("asset_count") or 0),
        "inScopeAssetCount": int(row.get("in_scope_asset_count") or 0),
        "createdAt": row.get("created_at"),
        "updatedAt": row.get("updated_at"),
    }


def serialize_asset(row: dict) -> dict:
    return {
        "id": row["id"],
        "assetKey": row["asset_key"],
        "ipAddress": row["ip_address"],
        "dnsName": row["dns_name"],
        "hostName": row["host_name"],
        "externalId": row["external_id"],
        "assetType": row["asset_type"],
        "onboardingTool": row.get("onboarding_tool") or "manual",
        "teamId": row.get("team_id"),
        "teamName": row.get("team_name") or "",
        "platform": row["platform"],
        "businessUnit": row["business_unit"],
        "criticality": row["criticality"],
        "internetExposed": row["internet_exposed"],
        "origin": row["origin"],
        "inScope": row["in_scope"],
        "firstSeenAt": row.get("first_seen_at"),
        "lastSeenAt": row.get("last_seen_at"),
        "updatedAt": row.get("updated_at"),
    }


def serialize_run(row: dict | None) -> dict | None:
    if not row:
        return None
    return {
        "id": row["id"],
        "customerId": row.get("customer_id"),
        "customerName": row["customer_name"],
        "ingestionKey": row.get("ingestion_key"),
        "workflow": row["workflow"],
        "sourceTool": row.get("source_tool"),
        "sourceLabel": row["source_label"],
        "reportPeriod": row["report_period"],
        "fileNames": row.get("file_names") or [],
        "sourceIds": row.get("source_ids") or [],
        "expectedFindings": int(row.get("expected_findings") or 0),
        "receivedFindings": int(row.get("received_findings") or 0),
        "weightedFindings": int(row.get("weighted_findings") or 0),
        "expectedChunks": int(row.get("expected_chunks") or 0),
        "receivedChunks": int(row.get("received_chunks") or 0),
        "status": row["status"],
        "dashboard": row.get("dashboard") or {},
        "inputSummary": row.get("input_summary") or {},
        "createdAt": row.get("created_at"),
        "finalizedAt": row.get("finalized_at"),
    }


def serialize_threat_import(row: dict | None) -> dict | None:
    if not row:
        return None
    return {
        "id": row["id"],
        "customerId": row["customer_id"],
        "ingestionKey": row["ingestion_key"],
        "sourceLabel": row["source_label"],
        "fileNames": row.get("file_names") or [],
        "expectedRecords": int(row.get("expected_records") or 0),
        "receivedRecords": int(row.get("received_records") or 0),
        "status": row["status"],
        "createdAt": row.get("created_at"),
        "finalizedAt": row.get("finalized_at"),
    }


def serialize_threat_record(row: dict) -> dict:
    return {
        "importId": row["import_id"],
        "cve": row["cve"],
        "vulnerabilityName": row["vulnerability_name"],
        "sourceTool": row["source_tool"],
        "sourceVulnerabilityId": row["source_vulnerability_id"],
        "ipAddress": row["ip_address"],
        "dnsName": row["dns_name"],
        "sourceLabel": row["source_label"],
        "severity": row["severity"],
        "patchPriority": row["patch_priority"],
        "exploitAvailable": row["exploit_available"],
        "vulnerabilityConfidence": row["vulnerability_confidence"],
        "exploitEvidence": row["exploit_evidence"],
        "description": row["description"],
        "remediation": row["remediation"],
        "kbLinks": row["kb_links"],
        "product": row["product"],
        "platformDetails": row["platform_details"],
        "namespace": row["namespace"],
        "deployment": row["deployment"],
        "image": row["image"],
        "component": row["component"],
        "fixable": row["fixable"],
        "fixedIn": row["fixed_in"],
        "cvssScore": (
            float(row["cvss_score"]) if row["cvss_score"] is not None else None
        ),
        "firstObserved": _calendar_date(row["first_observed"]),
        "lastObserved": _calendar_date(row["last_observed"]),
        "fileNames": row.get("file_names") or [],
        "finalizedAt": row.get("finalized_at"),
    }


def _serialize_inventory(row: dict) -> dict:
    return {
        "totalAssets": int(row.get("total_assets") or 0),
        "inScopeAssets": int(row.get("in_scope_assets") or 0),
        "manualAssets": int(row.get("manual_assets") or 0),
        "discoveredAssets": int(row.get("discovered_assets") or 0),
        "assetTypes": {
            key: int(value)
            for key, value in (row.get("asset_types") or {}).items()
        },
    }


def _calendar_date(value) -> str:
    if not value:
        return ""
    if hasattr(value, "date") and not hasattr(value, "day"):
        value = value.date()
    if hasattr(value, "isoformat"):
        return value.isoformat()[:10]
    return str(value)[:10]


def _finding_asset_match_sql(finding_alias: str, asset_alias: str) -> str:
    return f"""(
      {asset_alias}.asset_key IN (
        lower(NULLIF(trim({finding_alias}.ip_address), '')),
        lower(NULLIF(trim({finding_alias}.dns_name), ''))
      )
      OR lower(NULLIF(trim({asset_alias}.ip_address), '')) IN (
        lower(NULLIF(trim({finding_alias}.ip_address), '')),
        lower(NULLIF(trim({finding_alias}.dns_name), ''))
      )
      OR lower(NULLIF(trim({asset_alias}.dns_name), '')) IN (
        lower(NULLIF(trim({finding_alias}.ip_address), '')),
        lower(NULLIF(trim({finding_alias}.dns_name), ''))
      )
      OR EXISTS (
        SELECT 1 FROM customer_asset_aliases ownership_alias
        WHERE ownership_alias.customer_id = %(customer_id)s
          AND ownership_alias.asset_id = {asset_alias}.id
          AND ownership_alias.alias IN (
            lower(NULLIF(trim({finding_alias}.ip_address), '')),
            lower(NULLIF(trim({finding_alias}.dns_name), ''))
          )
      )
    )"""


def _inventory_scope_sql(alias: str) -> str:
    return f"""EXISTS (
      SELECT 1 FROM customer_assets scope_asset
      WHERE scope_asset.customer_id = %(customer_id)s
        AND scope_asset.in_scope
        AND {_finding_asset_match_sql(alias, "scope_asset")}
    )"""


def _asset_type_scope_sql(alias: str) -> str:
    return f"""(
      cardinality(%(asset_types)s::text[]) = 0
      OR EXISTS (
        SELECT 1 FROM customer_assets access_asset
        WHERE access_asset.customer_id = %(customer_id)s
          AND access_asset.in_scope
          AND access_asset.asset_type = ANY(%(asset_types)s::text[])
          AND {_finding_asset_match_sql(alias, "access_asset")}
      )
    )"""


def _team_scope_sql(alias: str) -> str:
    return f"""(
      %(team_id)s::uuid IS NULL
      OR EXISTS (
        SELECT 1 FROM customer_assets team_asset
        WHERE team_asset.customer_id = %(customer_id)s
          AND team_asset.team_id = %(team_id)s::uuid
          AND team_asset.in_scope
          AND {_finding_asset_match_sql(alias, "team_asset")}
      )
    )"""


def _asset_scope_sql(alias: str) -> str:
    return f"""(
      %(asset_id)s::uuid IS NULL
      OR EXISTS (
        SELECT 1 FROM customer_assets selected_asset
        WHERE selected_asset.customer_id = %(customer_id)s
          AND selected_asset.id = %(asset_id)s::uuid
          AND selected_asset.in_scope
          AND {_finding_asset_match_sql(alias, "selected_asset")}
      )
    )"""


def _empty_dashboard(customer: dict, inventory: dict) -> dict:
    return {
        "customer": customer,
        "latestRun": None,
        "currentPeriod": None,
        "previousPeriod": None,
        "comparisonAvailable": False,
        "metrics": {
            "totalOpen": 0,
            "affectedAssets": 0,
            "immediatePatch": 0,
            "exploitable": 0,
            "newFindings": 0,
            "fixedFindings": 0,
            "repeatedFindings": 0,
            "excludedByScope": 0,
        },
        "severity": {},
        "priority": {},
        "sources": {},
        "ageByPriority": [],
        "topAssets": [],
        "teamBreakdown": [],
        "selectedTeamId": None,
        "selectedAssetId": None,
        "trend": [],
        "inventory": inventory,
        "recentRuns": [],
    }
