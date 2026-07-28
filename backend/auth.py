from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets

from .errors import MVAError

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 3
SCRYPT_LENGTH = 64
SCRYPT_MAX_MEMORY = 64 * 1024 * 1024


def normalize_email(value: object) -> str:
    return str(value or "").strip().lower()[:254]


def validate_account(payload: dict | None, require_password: bool = True) -> dict:
    payload = payload or {}
    email = normalize_email(payload.get("email"))
    full_name = clean_text(payload.get("fullName"), 180)
    password = str(payload.get("password") or "")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise MVAError("Enter a valid email address.")
    if len(full_name) < 2:
        raise MVAError("Enter the user's full name.")
    if require_password:
        validate_password(password, email)
    return {"email": email, "fullName": full_name, "password": password}


def validate_password(password: str, email: str = "") -> str:
    if not isinstance(password, str) or len(password) < 12:
        raise MVAError("Password must contain at least 12 characters.")
    if len(password) > 128:
        raise MVAError("Password cannot exceed 128 characters.")
    if email and email.split("@")[0] in password.lower():
        raise MVAError("Password must not contain the email username.")
    return password


def hash_password(password: str) -> str:
    validate_password(password)
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAX_MEMORY,
        dklen=SCRYPT_LENGTH,
    )
    return "$".join(("scrypt", str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P), _b64(salt), _b64(derived)))


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, n_text, r_text, p_text, salt_text, hash_text = str(encoded_hash or "").split("$")
        if algorithm != "scrypt":
            return False
        expected = _unb64(hash_text)
        actual = hashlib.scrypt(
            password.encode(),
            salt=_unb64(salt_text),
            n=int(n_text),
            r=int(r_text),
            p=int(p_text),
            maxmem=SCRYPT_MAX_MEMORY,
            dklen=len(expected),
        )
        return hmac.compare_digest(expected, actual)
    except (ValueError, TypeError):
        return False


def create_session_secrets() -> dict:
    token = _b64(secrets.token_bytes(32))
    return {
        "token": token,
        "tokenHash": hash_opaque_token(token),
        "csrfToken": _b64(secrets.token_bytes(24)),
    }


def hash_opaque_token(token: object) -> str:
    return _b64(hashlib.sha256(str(token or "").encode()).digest())


def constant_time_equal(left: object, right: object) -> bool:
    return hmac.compare_digest(str(left or "").encode(), str(right or "").encode())


def login_key(ip_address: str, email: str) -> str:
    return hashlib.sha256(f"{ip_address}:{email}".encode()).hexdigest()


def clean_text(value: object, maximum: int) -> str:
    return str(value or "").replace("\x00", "").strip()[:maximum]


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
