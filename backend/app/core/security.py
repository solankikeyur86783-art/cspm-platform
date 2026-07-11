import secrets
import hashlib
import bcrypt as _bcrypt
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import JWTError, jwt

from app.core.config import settings
from app.core.logging import logger


ALGORITHM = settings.JWT_ALGORITHM


# ── Password ─────────────────────────────────────────────────────────────────

def _encode(password: str) -> bytes:
    """Encode and truncate to 72 bytes — bcrypt hard limit."""
    return password.encode("utf-8")[:72]


def hash_password(password: str) -> str:
    return _bcrypt.hashpw(_encode(password), _bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(_encode(plain), hashed.encode("utf-8"))
    except Exception:
        return False


# ── JWT ──────────────────────────────────────────────────────────────────────

def create_access_token(subject: str | Any, extra: dict | None = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {"sub": str(subject), "exp": expire, "type": "access"}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(subject: str | Any) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {"sub": str(subject), "exp": expire, "type": "refresh"}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        logger.warning(f"JWT decode failed: {exc}")
        raise


# ── API Keys ─────────────────────────────────────────────────────────────────

def generate_api_key() -> tuple[str, str]:
    """
    Returns (raw_key, hashed_key).
    Store only the hash; return the raw key once to the user.
    """
    raw = f"cspm_{secrets.token_urlsafe(32)}"
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def verify_api_key(raw: str, hashed: str) -> bool:
    return hashlib.sha256(raw.encode()).hexdigest() == hashed
