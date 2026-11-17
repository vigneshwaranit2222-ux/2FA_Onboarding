from datetime import datetime, timezone

import jwt
import pyotp
import pytest
from argon2 import PasswordHasher
from cryptography.fernet import Fernet

from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import LoginRequest
from app.services.auth_service import InvalidCredentialsError, authenticate_user
from app.services.totp_service import encrypt_totp_secret, _hash_recovery_code


class FakeSession:
    def __init__(self, user: User) -> None:
        self.user = user
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    async def scalar(self, _query):
        return self.user

    def add(self, value) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


def make_user() -> User:
    return User(
        id=41,
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
        failed_login_attempts=0,
        login_locked_until=None,
    )


def request(**overrides) -> LoginRequest:
    payload = {
        "email": "Ada@example.com",
        "password": "Correct-Horse7!Battery",
    }
    payload.update(overrides)
    return LoginRequest.model_validate(payload)


@pytest.mark.asyncio
async def test_password_login_issues_access_and_refresh_tokens(monkeypatch) -> None:
    secret = "test-jwt-secret-long-enough-for-hmac-testing"
    monkeypatch.setenv("JWT_SECRET_KEY", secret)
    user = make_user()
    db = FakeSession(user)

    pair = await authenticate_user(db, request())
    claims = jwt.decode(pair.access_token, secret, algorithms=["HS256"])

    assert claims["sub"] == str(user.id)
    assert claims["type"] == "access"
    assert claims["sid"] == pair.family_id
    assert claims["exp"] > claims["iat"]
    assert pair.refresh_token
    assert len(db.added) == 1 and isinstance(db.added[0], RefreshToken)
    assert db.added[0].token_hash != pair.refresh_token
    assert db.commits == 1


@pytest.mark.asyncio
async def test_wrong_password_increments_lockout_and_issues_no_token(monkeypatch) -> None:
    user = make_user()
    db = FakeSession(user)

    with pytest.raises(InvalidCredentialsError):
        await authenticate_user(db, request(password="Wrong-Password7!"))

    assert user.failed_login_attempts == 1
    assert user.login_locked_until is None
    assert db.commits == 1
    assert db.added == []


@pytest.mark.asyncio
async def test_inactive_or_unverified_account_cannot_login(monkeypatch) -> None:
    user = make_user()
    user.is_active = False
    with pytest.raises(InvalidCredentialsError):
        await authenticate_user(FakeSession(user), request())

    user.is_active = True
    user.phone_verified = False
    with pytest.raises(InvalidCredentialsError):
        await authenticate_user(FakeSession(user), request())


@pytest.mark.asyncio
async def test_totp_enabled_account_requires_and_consumes_valid_code(monkeypatch) -> None:
    secret = "test-jwt-secret-long-enough-for-hmac-testing"
    monkeypatch.setenv("JWT_SECRET_KEY", secret)
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    user = make_user()
    authenticator_secret = pyotp.random_base32()
    user.totp_enabled = True
    user.totp_secret_encrypted = encrypt_totp_secret(authenticator_secret)
    code = pyotp.TOTP(authenticator_secret).now()

    with pytest.raises(InvalidCredentialsError):
        await authenticate_user(FakeSession(user), request())

    pair = await authenticate_user(FakeSession(user), request(totp_code=code))
    assert pair.access_token
    assert user.totp_last_used_step is not None


@pytest.mark.asyncio
async def test_recovery_code_can_complete_mfa_login_once(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-long-enough-for-hmac-testing")
    user = make_user()
    user.totp_enabled = True
    recovery_code = "one-time-recovery-code-for-login"
    user.totp_recovery_codes = [_hash_recovery_code(user.id, recovery_code)]

    pair = await authenticate_user(FakeSession(user), request(recovery_code=recovery_code))
    assert pair.access_token
    assert user.totp_recovery_codes == []

    with pytest.raises(InvalidCredentialsError):
        await authenticate_user(FakeSession(user), request(recovery_code=recovery_code))
