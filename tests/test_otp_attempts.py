from datetime import datetime, timedelta, timezone
import pytest

from app.models.otp import OTPChallenge
from app.models.user import User
from app.services.otp_service import (
    InvalidOTPError,
    hash_otp,
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
        id=404,
        full_name="Margaret Hamilton",
        email="margaret@example.com",
        phone="+14155552675",
        password_hash="mock-argon2-hash",
        email_verified=False,
        phone_verified=False,
        is_verified=False,
        is_active=False,
    )


@pytest.mark.asyncio
async def test_wrong_otp_increments_attempts_counter(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_user()
    now = datetime.now(timezone.utc)
    challenge = OTPChallenge(
        id=4,
        user_id=user.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp("998877", user.id, "email_verification"),
        expires_at=now + timedelta(minutes=5),
        is_verified=False,
        attempts=0,
        resend_count=0,
        last_sent_at=now,
        created_at=now,
    )
    db = FakeSession(user, challenge)

    # First wrong attempt
    with pytest.raises(InvalidOTPError):
        await verify_otp(db, "email", user.email, "000000")

    assert challenge.attempts == 1
    assert db.commits == 1
    assert challenge.is_verified is False

    # Second wrong attempt
    with pytest.raises(InvalidOTPError):
        await verify_otp(FakeSession(user, challenge), "email", user.email, "111111")

    assert challenge.attempts == 2


@pytest.mark.asyncio
async def test_max_attempts_exhausted_rejects_even_correct_code(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    monkeypatch.setenv("OTP_MAX_ATTEMPTS", "5")
    user = make_user()
    now = datetime.now(timezone.utc)
    # Challenge already has 5 failed attempts
    challenge = OTPChallenge(
        id=5,
        user_id=user.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp("998877", user.id, "email_verification"),
        expires_at=now + timedelta(minutes=5),
        is_verified=False,
        attempts=5,
        resend_count=0,
        last_sent_at=now,
        created_at=now,
    )
    db = FakeSession(user, challenge)

    # Submitting the correct code should fail because attempts >= max_attempts
    with pytest.raises(InvalidOTPError):
        await verify_otp(db, "email", user.email, "998877")

    assert challenge.is_verified is False
    assert user.email_verified is False

