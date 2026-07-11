import pytest
import time
from app.core.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    decode_token, generate_api_key, verify_api_key,
)


def test_password_hash_and_verify():
    password = "MySecurePass123!"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed)


def test_wrong_password_fails():
    hashed = hash_password("correct-password")
    assert not verify_password("wrong-password", hashed)


def test_access_token_contains_subject():
    token = create_access_token("user-123")
    payload = decode_token(token)
    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"


def test_access_token_with_extra_claims():
    token = create_access_token("user-456", {"role": "admin", "org": "acme"})
    payload = decode_token(token)
    assert payload["sub"] == "user-456"
    assert payload["role"] == "admin"
    assert payload["org"] == "acme"


def test_refresh_token_type():
    token = create_refresh_token("user-789")
    payload = decode_token(token)
    assert payload["sub"] == "user-789"
    assert payload["type"] == "refresh"


def test_invalid_token_raises():
    from jose import JWTError
    with pytest.raises(JWTError):
        decode_token("not.a.valid.token")


def test_tampered_token_raises():
    from jose import JWTError
    token = create_access_token("user-000")
    tampered = token[:-5] + "XXXXX"
    with pytest.raises(JWTError):
        decode_token(tampered)


def test_api_key_format():
    raw, hashed = generate_api_key()
    assert raw.startswith("cspm_")
    assert len(raw) > 20
    assert len(hashed) == 64  # SHA-256 hex


def test_api_key_verify():
    raw, hashed = generate_api_key()
    assert verify_api_key(raw, hashed)
    assert not verify_api_key("wrong_key", hashed)


def test_api_key_unique():
    keys = [generate_api_key()[0] for _ in range(10)]
    assert len(set(keys)) == 10  # All unique
