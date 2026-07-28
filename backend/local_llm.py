from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from .config import Settings
from .errors import MVAError


class LocalLLMClient:
    """Single server-side adapter for native Ollama and OpenAI-compatible APIs."""

    def __init__(self, settings: Settings):
        self.base_url = self._base_url(settings.ai_base_url)
        self.model = settings.ai_model.strip()
        self.api_style = settings.ai_api_style
        self.api_key = settings.ai_api_key.strip()
        self.auth_header = settings.ai_auth_header.strip() or "Authorization"
        self.auth_scheme = settings.ai_auth_scheme.strip()
        self.timeout = settings.ai_timeout_seconds
        self.tls_verify = settings.ai_tls_verify
        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", self.auth_header):
            raise RuntimeError("AI_AUTH_HEADER is not a valid HTTP header name.")

    def status(self) -> dict:
        return {
            "configured": bool(self.base_url and self.model),
            "provider": "Local Ollama" if self.api_style == "ollama" else "OpenAI-compatible Local AI",
            "apiStyle": self.api_style,
            "model": self.model,
            "baseUrl": self.base_url,
            "authenticationConfigured": bool(self.api_key),
        }

    def test(self) -> dict:
        path = "/api/tags" if self.api_style == "ollama" else "/models"
        payload = self._request("GET", path, timeout=20)
        if self.api_style == "ollama":
            models = [item.get("name") or item.get("model") for item in payload.get("models", [])]
        else:
            models = [item.get("id") for item in payload.get("data", [])]
        models = [str(model) for model in models if model]
        installed = any(model == self.model or model.split(":")[0] == self.model.split(":")[0] for model in models)
        if models and not installed:
            raise MVAError(f"The AI server is reachable, but model '{self.model}' is not available.", 503)
        return {**self.status(), "reachable": True, "modelInstalled": installed or not models, "installedModels": models}

    def chat(
        self,
        messages: list[dict],
        *,
        json_mode: bool = False,
        temperature: float = 0.1,
        max_tokens: int = 8192,
    ) -> dict:
        if not self.base_url or not self.model:
            raise MVAError("The local AI model is not configured on the MVA API.", 503)
        max_tokens = max(16, min(32768, int(max_tokens or 8192)))
        if self.api_style == "ollama":
            payload = self._request("POST", "/api/chat", json={
                "model": self.model,
                "messages": messages,
                "stream": False,
                **({"format": "json"} if json_mode else {}),
                "options": {"temperature": temperature, "num_predict": max_tokens},
            })
            content = str((payload.get("message") or {}).get("content") or payload.get("response") or "").strip()
            returned_model = payload.get("model") or self.model
            finish_reason = payload.get("done_reason") or ""
        else:
            payload = self._request("POST", "/chat/completions", json={
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": False,
                **({"response_format": {"type": "json_object"}} if json_mode else {}),
            })
            choice = (payload.get("choices") or [{}])[0]
            content = str((choice.get("message") or {}).get("content") or "").strip()
            returned_model = payload.get("model") or self.model
            finish_reason = choice.get("finish_reason") or ""
        if not content:
            raise MVAError("The local AI model returned no content.", 502)
        return {"content": content, "model": returned_model, "doneReason": finish_reason}

    def _request(self, method: str, path: str, *, json: dict | None = None, timeout: int | None = None) -> dict:
        headers = {"Accept": "application/json"}
        if json is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers[self.auth_header] = f"{self.auth_scheme} {self.api_key}".strip()
        try:
            response = httpx.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                json=json,
                timeout=timeout or self.timeout,
                verify=self.tls_verify,
                follow_redirects=False,
            )
            payload = response.json() if response.content else {}
        except httpx.TimeoutException as error:
            raise MVAError("The local AI request timed out.", 504) from error
        except (httpx.NetworkError, ValueError) as error:
            raise MVAError("The MVA API cannot reach the configured local AI server.", 503) from error
        if not response.is_success:
            detail = payload.get("error") or payload.get("message") or f"Local AI server returned HTTP {response.status_code}."
            if isinstance(detail, dict):
                detail = detail.get("message") or str(detail)
            raise MVAError(str(detail)[:1000], response.status_code if 400 <= response.status_code < 600 else 502)
        return payload

    @staticmethod
    def _base_url(value: str) -> str:
        text = str(value or "").strip().rstrip("/")
        if not text:
            return ""
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise RuntimeError("AI_BASE_URL must be an HTTP(S) URL without embedded credentials.")
        return text
