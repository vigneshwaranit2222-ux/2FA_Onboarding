from datetime import datetime, timedelta, timezone
import pytest

from app.models.otp import OTPChallenge
from app.models.user import User
from app.services.otp_service import (
    InvalidOTPError,
    hash_otp,
    issue_otp,
    otp_matches,
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


def make_user(user_id: int, email: str, phone: str) -> User:
    return User(
        id=user_id,
        full_name=f"User {user_id}",
        email=email,
        phone=phone,
        password_hash="mock-argon2-hash",
        email_verified=False,
        phone_verified=False,
        is_verified=False,
        is_active=False,
    )


def test_plaintext_otp_is_never_stored_in_database(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    code = "789123"
    user_id = 606
    purpose = "email_verification"

    digest = hash_otp(code, user_id, purpose)
    # Plaintext OTP must never appear inside hash
    assert code not in digest
    assert len(digest) == 64


@pytest.mark.asyncio
async def test_cross_user_verification_attack_prevented(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user_a = make_user(1, "alice@example.com", "+14155551111")
    user_b = make_user(2, "bob@example.com", "+14155552222")
    now = datetime.now(timezone.utc)

    # Challenge was issued for User A
    code = "654321"
    challenge_a = OTPChallenge(
        id=10,
        user_id=user_a.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp(code, user_a.id, "email_verification"),
        expires_at=now + timedelta(minutes=5),
        is_verified=False,
        attempts=0,
        resend_count=0,
        last_sent_at=now,
        created_at=now,
    )

    # Bob attempts to verify his email using Alice's code or Alice's challenge
    db = FakeSession(user_b, challenge_a)

    with pytest.raises(InvalidOTPError):
        # Bob provides his email with Alice's code
        await verify_otp(db, "email", user_b.email, code)

    # Alice's challenge is not verified
    assert challenge_a.is_verified is False
    assert user_b.email_verified is False


@pytest.mark.asyncio
async def test_cross_purpose_verification_attack_prevented(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_user(3, "charlie@example.com", "+14155553333")
    now = datetime.now(timezone.utc)

    code = "123789"
    # Challenge issued for email_verification
    email_challenge = OTPChallenge(
        id=11,
        user_id=user.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp(code, user.id, "email_verification"),
        expires_at=now + timedelta(minutes=5),
        is_verified=False,
        attempts=0,
        resend_count=0,
        last_sent_at=now,
        created_at=now,
    )

    # Charlie attempts to use this email OTP to verify his phone!
    db = FakeSession(user, email_challenge)

    with pytest.raises(InvalidOTPError):
        await verify_otp(db, "whatsapp", user.phone, code)

    assert email_challenge.is_verified is False
    assert user.phone_verified is False


@pytest.mark.asyncio
async def test_replay_attack_prevented_after_successful_verification(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_user(4, "dave@example.com", "+14155554444")
    now = datetime.now(timezone.utc)

    code = "998877"
    challenge = OTPChallenge(
        id=12,
        user_id=user.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp(code, user.id, "email_verification"),
        expires_at=now + timedelta(minutes=5),
        is_verified=False,
        attempts=0,
        resend_count=0,
        last_sent_at=now,
        created_at=now,
    )

    # First verification succeeds
    db1 = FakeSession(user, challenge)
    assert await verify_otp(db1, "email", user.email, code) is True
    assert challenge.is_verified is True

    # Attacker tries to replay the same code against the now-verified challenge
    db2 = FakeSession(user, challenge)
    with pytest.raises(InvalidOTPError):
        await verify_otp(db2, "email", user.email, code)

