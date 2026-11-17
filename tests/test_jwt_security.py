from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.core.security import get_current_user
from app.models.user import User


class FakeSession:
    def __init__(self, user, active_session=1) -> None:
        self.user = user
        self.active_session = active_session
        self.calls = 0

    async def scalar(self, _query):
        self.calls += 1
        return self.user if self.calls == 1 else self.active_session


def make_user(*, active: bool = True) -> User:
    return User(
        id=29,
        full_name="Ada Lovelace",
        email="ada@example.com",
        phone="+14155552671",
        password_hash="not-used",
        is_active=active,
    )


def make_token(secret: str, *, expires: datetime) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": "29",
            "sid": "12345678-1234-5678-1234-567812345678",
            "iat": now,
            "exp": expires,
            "type": "access",
        },
        secret,
        algorithm="HS256",
    )


@pytest.mark.asyncio
async def test_valid_access_token_resolves_active_user(monkeypatch) -> None:
    secret = "test-jwt-secret-long-enough-for-hmac-testing"
    monkeypatch.setenv("JWT_SECRET_KEY", secret)
    user = make_user()
    token = make_token(secret, expires=datetime.now(timezone.utc) + timedelta(minutes=5))
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    result = await get_current_user(credentials=credentials, db=FakeSession(user))
    assert result is user


@pytest.mark.asyncio
async def test_expired_token_is_rejected(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-long-enough-for-hmac-testing")
    token = make_token(
        "test-jwt-secret-long-enough-for-hmac-testing",
        expires=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(HTTPException) as exc:
        await get_current_user(credentials=credentials, db=FakeSession(make_user()))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_inactive_account_cannot_use_access_token(monkeypatch) -> None:
    secret = "test-jwt-secret-long-enough-for-hmac-testing"
    monkeypatch.setenv("JWT_SECRET_KEY", secret)
    token = make_token(secret, expires=datetime.now(timezone.utc) + timedelta(minutes=5))
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(HTTPException) as exc:
        await get_current_user(credentials=credentials, db=FakeSession(make_user(active=False)))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_revoked_session_invalidates_access_token(monkeypatch) -> None:
    secret = "test-jwt-secret-long-enough-for-hmac-testing"
    monkeypatch.setenv("JWT_SECRET_KEY", secret)
    token = make_token(secret, expires=datetime.now(timezone.utc) + timedelta(minutes=5))
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(HTTPException) as exc:
        await get_current_user(
            credentials=credentials,
            db=FakeSession(make_user(), active_session=None),
        )
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_missing_or_invalid_token_is_rejected_without_leaking_details(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-long-enough-for-hmac-testing")
    with pytest.raises(HTTPException) as missing:
        await get_current_user(credentials=None, db=FakeSession(make_user()))
    assert missing.value.status_code == 401

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="not-a-jwt")
    with pytest.raises(HTTPException) as invalid:
        await get_current_user(credentials=credentials, db=FakeSession(make_user()))
    assert invalid.value.status_code == 401
