from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
import hashlib

import httpx
import jwt
import pytest
from argon2 import PasswordHasher

from app.database.session import get_db
from app.main import app
from app.models.refresh_token import RefreshToken
from app.models.user import User


SESSION_ID = "11111111-1111-4111-8111-111111111111"
JWT_SECRET = "test-jwt-secret-long-enough-for-hmac-testing"


class FakeSession:
    def __init__(self, *results, rows=None) -> None:
        self.results = list(results)
        self.rows = list(rows or [])
        self.added = []
        self.commits = 0
        self.rollbacks = 0
        self.refreshes = 0

    async def scalar(self, _query):
        if self.results:
            return self.results.pop(0)
        return self.added[-1] if self.added else None

    async def scalars(self, _query):
        return Result([])

    def add(self, value) -> None:
        self.added.append(value)

    async def flush(self) -> None:
        for row in self.added:
            if row.id is None:
                row.id = max([item.id or 0 for item in self.rows] + [0]) + 1
                self.rows.append(row)

    async def execute(self, _query):
        now = datetime.now(timezone.utc)
        family_id = self.rows[0].family_id if self.rows else None
        for row in self.rows:
            if row.family_id == family_id and row.revoked_at is None:
                row.revoked_at = now

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1

    async def refresh(self, _instance) -> None:
        self.refreshes += 1


class Result:
    def __init__(self, values) -> None:
        self.values = values

    def all(self):
        return self.values


def make_user(*, totp_enabled=False, active=True) -> User:
    return User(
        id=51,
        full_name="Ada Lovelace",
        email="ada@example.com",
        phone="+14155552671",
        password_hash=PasswordHasher().hash("Correct-Horse7!Battery"),
        email_verified=True,
        phone_verified=True,
        is_verified=True,
        is_active=active,
        totp_enabled=totp_enabled,
        totp_secret_encrypted=None,
        totp_confirmed_at=None,
        totp_last_used_step=None,
        totp_failed_attempts=0,
        totp_locked_until=None,
        totp_recovery_codes=[],
        failed_login_attempts=0,
        login_locked_until=None,
    )


def make_refresh(raw: str, *, revoked_at=None) -> RefreshToken:
    now = datetime.now(timezone.utc)
    return RefreshToken(
        id=1,
        user_id=51,
        family_id=SESSION_ID,
        token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        expires_at=now + timedelta(days=2),
        created_at=now,
        revoked_at=revoked_at,
    )


def access_token(user_id: int = 51) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(user_id),
            "sid": SESSION_ID,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "type": "access",
        },
        JWT_SECRET,
        algorithm="HS256",
    )


async def send_request(method, path, db, *, payload=None, token=None):
    async def override_get_db() -> AsyncIterator[FakeSession]:
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            return await client.request(
                method,
                path,
                json=payload,
                headers={"Authorization": f"Bearer {token}"} if token else {},
            )
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_login_requires_verified_account_and_returns_both_tokens(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    db = FakeSession(make_user())
    response = await send_request(
        "POST",
        "/api/v1/auth/login",
        db,
        payload={"email": "Ada@example.com", "password": "Correct-Horse7!Battery"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["refresh_token"]
    claims = jwt.decode(body["access_token"], JWT_SECRET, algorithms=["HS256"])
    assert claims["sub"] == "51"
    assert claims["type"] == "access"
    assert claims["sid"] == db.added[0].family_id
    assert db.added[0].token_hash != body["refresh_token"]


@pytest.mark.asyncio
async def test_login_does_not_issue_token_before_totp(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    db = FakeSession(make_user(totp_enabled=True))
    response = await send_request(
        "POST",
        "/api/v1/auth/login",
        db,
        payload={"email": "ada@example.com", "password": "Correct-Horse7!Battery"},
    )
    assert response.status_code == 401
    assert db.added == []


@pytest.mark.asyncio
async def test_refresh_route_rotates_token(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    old = make_refresh("old-refresh-token")
    db = FakeSession(old, make_user(), rows=[old])

    response = await send_request(
        "POST",
        "/api/v1/auth/refresh",
        db,
        payload={"refresh_token": "old-refresh-token"},
    )
    assert response.status_code == 200
    assert response.json()["refresh_token"] != "old-refresh-token"
    assert old.revoked_at is not None
    assert old.replaced_by_token_id == 2


@pytest.mark.asyncio
async def test_logout_revokes_refresh_session(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    refresh = make_refresh("current-refresh-token")
    db = FakeSession(make_user(), 1, refresh, rows=[refresh])

    response = await send_request(
        "POST",
        "/api/v1/auth/logout",
        db,
        payload={"refresh_token": "current-refresh-token"},
        token=access_token(),
    )
    assert response.status_code == 200
    assert refresh.revoked_at is not None


@pytest.mark.asyncio
async def test_me_endpoint_requires_access_token_and_returns_safe_profile(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    user = make_user()
    db = FakeSession(user, 1)
    response = await send_request("GET", "/api/v1/auth/me", db, token=access_token())

    assert response.status_code == 200
    profile = response.json()
    assert profile["email"] == "ada@example.com"
    assert profile["email_verified"] is True
    assert profile["totp_enabled"] is False
    assert "password_hash" not in profile


@pytest.mark.asyncio
async def test_phone_profile_update_disables_account_and_revokes_refresh(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    user = make_user()
    refresh = make_refresh("current-refresh-token")
    db = FakeSession(user, 1, None, rows=[refresh])
    response = await send_request(
        "PATCH",
        "/api/v1/auth/me",
        db,
        payload={"phone": "+1 (212) 555-0101"},
        token=access_token(),
    )

    assert response.status_code == 200
    assert response.json()["phone"] == "+12125550101"
    assert response.json()["phone_verified"] is False
    assert response.json()["is_active"] is False
    assert refresh.revoked_at is not None
