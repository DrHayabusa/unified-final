from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote_plus


def _text(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _boolean(name: str, default: bool = False) -> bool:
    value = _text(name, "true" if default else "false").lower()
    return value in {"1", "true", "yes", "on"}


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(_text(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def read_secret(file_name: str, direct_value: str = "") -> str:
    path = _text(file_name)
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return _text(direct_value)


@dataclass(frozen=True)
class Settings:
    environment: str
    host: str
    port: int
    database_url: str
    database_pool_min: int
    database_pool_max: int
    cors_origins: tuple[str, ...]
    trusted_hosts: tuple[str, ...]
    cookie_secure: bool
    cookie_domain: str | None
    session_hours: int
    max_request_bytes: int
    frontend_dist: Path
    ai_base_url: str
    ai_model: str
    ai_api_style: str
    ai_api_key: str
    ai_auth_header: str
    ai_auth_scheme: str
    ai_timeout_seconds: int
    ai_tls_verify: bool

    @classmethod
    def from_environment(cls) -> "Settings":
        environment = _text("APP_ENV", "development").lower()
        database_url = _text("DATABASE_URL") or _database_url(environment)
        ai_base_url = _text("AI_BASE_URL") or _text("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        ai_model = _text("AI_MODEL") or _text("OLLAMA_MODEL", "gemma3:12b")
        ai_key = read_secret("AI_API_KEY_FILE", "AI_API_KEY") or read_secret("OLLAMA_API_KEY_FILE", "OLLAMA_API_KEY")
        api_style = _text("AI_API_STYLE", "ollama").lower()
        if api_style not in {"ollama", "openai"}:
            raise RuntimeError("AI_API_STYLE must be 'ollama' or 'openai'.")
        origins = tuple(item.strip() for item in _text(
            "CORS_ORIGINS",
            "http://127.0.0.1:8890,http://127.0.0.1:8891",
        ).split(",") if item.strip())
        trusted_hosts = tuple(item.strip() for item in _text(
            "TRUSTED_HOSTS",
            "127.0.0.1,localhost",
        ).split(",") if item.strip())
        cookie_secure = _boolean("COOKIE_SECURE", environment == "production")
        if environment == "production" and not cookie_secure:
            raise RuntimeError("COOKIE_SECURE must be true in production.")
        return cls(
            environment=environment,
            host=_text("HOST", "0.0.0.0"),
            port=_integer("PORT", 8787, 1, 65535),
            database_url=database_url,
            database_pool_min=_integer("DATABASE_POOL_MIN", 2, 1, 50),
            database_pool_max=_integer("DATABASE_POOL_MAX", 15, 2, 100),
            cors_origins=origins,
            trusted_hosts=trusted_hosts,
            cookie_secure=cookie_secure,
            cookie_domain=_text("COOKIE_DOMAIN") or None,
            session_hours=_integer("SESSION_HOURS", 8, 1, 72),
            max_request_bytes=_integer("MAX_REQUEST_BYTES", 32 * 1024 * 1024, 1024, 128 * 1024 * 1024),
            frontend_dist=Path(_text("FRONTEND_DIST", "/app/frontend_dist")),
            ai_base_url=ai_base_url,
            ai_model=ai_model,
            ai_api_style=api_style,
            ai_api_key=ai_key,
            ai_auth_header=_text("AI_AUTH_HEADER") or _text("OLLAMA_AUTH_HEADER", "Authorization"),
            ai_auth_scheme=_text("AI_AUTH_SCHEME") or _text("OLLAMA_AUTH_SCHEME", "Bearer"),
            ai_timeout_seconds=_integer("AI_TIMEOUT_SECONDS", 600, 5, 1800),
            ai_tls_verify=_boolean("AI_TLS_VERIFY", True),
        )


def _database_url(environment: str) -> str:
    user = _text("DATABASE_USER", "mva")
    password = read_secret("DATABASE_PASSWORD_FILE", "DATABASE_PASSWORD")
    if not password:
        password = _text("MVA_POSTGRES_PASSWORD")
    if not password:
        if environment == "production":
            raise RuntimeError("Set DATABASE_PASSWORD_FILE or DATABASE_PASSWORD in production.")
        password = "mva_local_only"
    host = _text("DATABASE_HOST", "127.0.0.1")
    port = _integer("DATABASE_PORT", 55432, 1, 65535)
    database = _text("DATABASE_NAME", "mva")
    return f"postgresql://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{quote_plus(database)}"
