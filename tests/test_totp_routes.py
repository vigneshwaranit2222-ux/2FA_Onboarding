from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pyotp
import pytest
from argon2 import PasswordHasher
from cryptography.fernet import Fernet

from app.database.session import get_db
from app.main import app
from app.models.user import User
from app.services.totp_service import decrypt_totp_secret


class FakeSession:
    def __init__(self, user: User) -> None:
        self.user = user
        self.commits = 0
        self.rollbacks = 0
        self.scalar_calls = 0

    async def scalar(self, _query):
        self.scalar_calls += 1
        return self.user if self.scalar_calls == 1 else 1

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


def create_user() -> User:
    return User(
        id=77,
        full_name="Ada Lovelace",
        email="ada@example.com",
        phone="+14155552671",
        password_hash=PasswordHasher().hash("Correct-Horse7!Battery"),
        email_verified=True,
        phone_verified=True,
        is_verified=True,
        is_active=True,
        totp_enabled=False,
        totp_secret_encrypted=None,
        totp_confirmed_at=None,
        totp_last_used_step=None,
        totp_failed_attempts=0,
        totp_locked_until=None,
        totp_recovery_codes=[],
    )


def create_token(monkeypatch) -> str:
    secret = "test-jwt-secret-long-enough-for-hmac-testing"
    monkeypatch.setenv("JWT_SECRET_KEY", secret)
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": "77",
            "sid": "12345678-1234-5678-1234-567812345678",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "type": "access",
        },
        secret,
        algorithm="HS256",
    )


async def request_as_user(method: str, path: str, db: FakeSession, token: str, payload=None):
    db.scalar_calls = 0

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
async def test_totp_enrollment_and_recovery_disable_flow(monkeypatch) -> None:
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    user = create_user()
    db = FakeSession(user)
    token = create_token(monkeypatch)

    setup = await request_as_user("POST", "/api/v1/auth/totp/setup", db, token)
    assert setup.status_code == 200
    assert setup.json()["provisioning_uri"].startswith("otpauth://totp/")
    assert setup.json()["qr_code_data_uri"].startswith("data:image/png;base64,")
    assert user.totp_enabled is False
    assert setup.json().get("secret") is None

    secret = decrypt_totp_secret(user.totp_secret_encrypted)
    code = pyotp.TOTP(secret).now()
    enrollment = await request_as_user(
        "POST",
        "/api/v1/auth/totp/verify",
        db,
        token,
        {"code": code},
    )
    assert enrollment.status_code == 200
    recovery_codes = enrollment.json()["recovery_codes"]
    assert user.totp_enabled is True
    assert len(recovery_codes) == 10
    assert all(code not in user.totp_recovery_codes for code in recovery_codes)

    replay = await request_as_user(
        "POST",
        "/api/v1/auth/totp/verify",
        db,
        token,
        {"code": code},
    )
    assert replay.status_code == 409

    disabled = await request_as_user(
        "POST",
        "/api/v1/auth/totp/disable",
        db,
        token,
        {
            "current_password": "Correct-Horse7!Battery",
            "recovery_code": recovery_codes[0],
        },
    )
    assert disabled.status_code == 200
    assert user.totp_enabled is False
    assert user.totp_secret_encrypted is None


@pytest.mark.asyncio
async def test_totp_setup_requires_access_token() -> None:
    response = await request_as_user(
        "POST",
        "/api/v1/auth/totp/setup",
        FakeSession(create_user()),
        token="",
    )
    assert response.status_code == 401
