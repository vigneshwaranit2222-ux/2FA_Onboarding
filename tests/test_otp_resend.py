from datetime import datetime, timedelta, timezone
import pytest

from app.models.otp import OTPChallenge
from app.models.user import User
from app.services.otp_service import (
    hash_otp,
    issue_otp,
    otp_matches,
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
        id=505,
        full_name="Mary Jackson",
        email="mary@example.com",
        phone="+14155552676",
        password_hash="mock-argon2-hash",
        email_verified=False,
        phone_verified=False,
        is_verified=False,
        is_active=False,
    )


@pytest.mark.asyncio
async def test_resend_blocked_during_cooldown(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    monkeypatch.setenv("OTP_RESEND_COOLDOWN_SECONDS", "60")
    user = make_user()
    now = datetime.now(timezone.utc)
    # Challenge sent 30 seconds ago (cooldown is 60s)
    challenge = OTPChallenge(
        id=6,
        user_id=user.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp("123456", user.id, "email_verification"),
        expires_at=now + timedelta(minutes=5),
        is_verified=False,
        attempts=0,
        resend_count=0,
        last_sent_at=now - timedelta(seconds=30),
        created_at=now - timedelta(seconds=30),
    )
    db = FakeSession(user, challenge)
    provider_called = False

    async def deliver(_recipient: str, _code: str) -> None:
        nonlocal provider_called
        provider_called = True

    result = await issue_otp(db, "email", user.email, deliver)
    assert result is False
    assert provider_called is False
    assert db.commits == 0


@pytest.mark.asyncio
async def test_resend_allowed_after_cooldown_replaces_otp(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    monkeypatch.setenv("OTP_RESEND_COOLDOWN_SECONDS", "60")
    user = make_user()
    now = datetime.now(timezone.utc)
    # Challenge sent 70 seconds ago (cooldown passed)
    challenge = OTPChallenge(
        id=6,
        user_id=user.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp("123456", user.id, "email_verification"),
        expires_at=now + timedelta(minutes=4),
        is_verified=False,
        attempts=2,
        resend_count=0,
        last_sent_at=now - timedelta(seconds=70),
        created_at=now - timedelta(seconds=70),
    )
    db = FakeSession(user, challenge)
    delivered_codes = []

    async def deliver(_recipient: str, code: str) -> None:
        delivered_codes.append(code)

    result = await issue_otp(db, "email", user.email, deliver)
    assert result is True
    assert len(delivered_codes) == 1
    new_code = delivered_codes[0]

    # Verify challenge updated
    assert challenge.resend_count == 1
    assert challenge.attempts == 0  # Attempts reset on new OTP issuance
    assert challenge.otp_hash != hash_otp("123456", user.id, "email_verification")
    assert otp_matches(new_code, user.id, "email_verification", challenge.otp_hash)
    assert db.commits == 1


@pytest.mark.asyncio
async def test_resend_blocked_when_max_resends_reached(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    monkeypatch.setenv("OTP_MAX_RESENDS", "3")
    user = make_user()
    now = datetime.now(timezone.utc)
    # Challenge has already reached 3 resends, even if cooldown passed
    challenge = OTPChallenge(
        id=7,
        user_id=user.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp("123456", user.id, "email_verification"),
        expires_at=now + timedelta(minutes=4),
        is_verified=False,
        attempts=0,
        resend_count=3,
        last_sent_at=now - timedelta(seconds=120),
        created_at=now - timedelta(seconds=120),
    )
    db = FakeSession(user, challenge)
    provider_called = False

    async def deliver(_recipient: str, _code: str) -> None:
        nonlocal provider_called
        provider_called = True

    result = await issue_otp(db, "email", user.email, deliver)
    assert result is False
    assert provider_called is False

