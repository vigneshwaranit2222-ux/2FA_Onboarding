from datetime import datetime, timedelta, timezone
import pytest

from app.models.otp import OTPChallenge
from app.models.user import User
from app.services.otp_service import (
    InvalidOTPError,
    get_otp_ttl_seconds,
    hash_otp,
    issue_otp,
    verify_otp,
)


class FakeSession:
    def __init__(self, *results) -> None:
        self.results = list(results)
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    async def scalar(self, _query):
        return self.results.pop(0)

    def add(self, value) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


def make_user() -> User:
    return User(
        id=303,
        full_name="Dorothy Vaughan",
        email="dorothy@example.com",
        phone="+14155552674",
        password_hash="mock-argon2-hash",
        email_verified=False,
        phone_verified=False,
        is_verified=False,
        is_active=False,
    )


def test_configurable_otp_expire_minutes(monkeypatch) -> None:
    monkeypatch.setenv("OTP_EXPIRE_MINUTES", "10")
    assert get_otp_ttl_seconds() == 600

    monkeypatch.setenv("OTP_EXPIRE_MINUTES", "3")
    assert get_otp_ttl_seconds() == 180

    monkeypatch.delenv("OTP_EXPIRE_MINUTES", raising=False)
    monkeypatch.setenv("OTP_TTL_SECONDS", "450")
    assert get_otp_ttl_seconds() == 450


@pytest.mark.asyncio
async def test_expired_otp_cannot_be_verified(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_user()
    now = datetime.now(timezone.utc)
    # Challenge expired 1 second ago
    expired_challenge = OTPChallenge(
        id=3,
        user_id=user.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp("123456", user.id, "email_verification"),
        expires_at=now - timedelta(seconds=1),
        is_verified=False,
        attempts=0,
        resend_count=0,
        last_sent_at=now - timedelta(minutes=6),
        created_at=now - timedelta(minutes=6),
    )
    db = FakeSession(user, expired_challenge)

    with pytest.raises(InvalidOTPError):
        await verify_otp(db, "email", user.email, "123456")

    # Expired code should not increment attempts or verify
    assert expired_challenge.attempts == 0
    assert expired_challenge.is_verified is False
    assert user.email_verified is False


@pytest.mark.asyncio
async def test_reissuing_otp_after_expiration_creates_new_challenge(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_user()
    now = datetime.now(timezone.utc)
    # Existing challenge expired
    expired_challenge = OTPChallenge(
        id=3,
        user_id=user.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp("123456", user.id, "email_verification"),
        expires_at=now - timedelta(minutes=1),
        is_verified=False,
        attempts=0,
        resend_count=1,
        last_sent_at=now - timedelta(minutes=6),
        created_at=now - timedelta(minutes=6),
    )
    db = FakeSession(user, expired_challenge)
    sent_codes = []

    async def deliver(recipient: str, code: str) -> None:
        sent_codes.append(code)

    success = await issue_otp(db, "email", user.email, deliver)
    assert success is True
    assert len(sent_codes) == 1
    # When previous challenge expired, a new challenge is added to db
    assert len(db.added) == 1
    new_challenge = db.added[0]
    assert new_challenge.expires_at > now
    assert new_challenge.attempts == 0
    assert new_challenge.resend_count == 0

