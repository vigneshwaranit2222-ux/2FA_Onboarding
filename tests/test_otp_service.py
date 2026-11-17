from datetime import datetime, timedelta, timezone

import pytest

from app.models.otp import OTPChallenge
from app.models.user import User
from app.services.otp_service import (
    InvalidOTPError,
    OTPDeliveryError,
    generate_otp,
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


def make_user() -> User:
    return User(
        id=17,
        full_name="Ada Lovelace",
        email="ada@example.com",
        phone="+14155552671",
        password_hash="not-used-in-this-test",
        email_verified=False,
        phone_verified=False,
        is_verified=False,
        is_active=False,
    )


def make_challenge(
    monkeypatch,
    *,
    code: str = "123456",
    expires_at: datetime | None = None,
    attempts: int = 0,
    resend_count: int = 0,
    last_sent_at: datetime | None = None,
) -> OTPChallenge:
    monkeypatch.setenv("OTP_HASH_SECRET", "test-only-secret-value-that-is-long-enough")
    now = datetime.now(timezone.utc)
    return OTPChallenge(
        id=42,
        user_id=17,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp(code, 17, "email_verification"),
        expires_at=expires_at or now + timedelta(minutes=5),
        is_verified=False,
        attempts=attempts,
        resend_count=resend_count,
        last_sent_at=last_sent_at or now - timedelta(minutes=2),
        created_at=now - timedelta(minutes=2),
    )


def test_otp_is_six_digits_and_hash_is_bound_to_user_and_purpose(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "test-only-secret-value-that-is-long-enough")
    code = generate_otp()
    digest = hash_otp(code, 17, "email_verification")

    assert len(code) == 6 and code.isdigit()
    assert code not in digest
    assert otp_matches(code, 17, "email_verification", digest)
    assert not otp_matches(code, 18, "email_verification", digest)
    assert not otp_matches(code, 17, "phone_verification", digest)


@pytest.mark.asyncio
async def test_issue_email_code_stores_only_hash_and_uses_provider(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "test-only-secret-value-that-is-long-enough")
    user = make_user()
    db = FakeSession(user, None)
    sent = []

    async def deliver(recipient: str, code: str) -> None:
        sent.append((recipient, code))

    issued = await issue_otp(db, "email", user.email, deliver)
    challenge = db.added[0]

    assert issued is True
    assert sent[0][0] == user.email
    assert len(sent[0][1]) == 6
    assert challenge.otp_hash != sent[0][1]
    assert challenge.purpose == "email_verification"
    assert challenge.resend_count == 0
    assert db.commits == 1


@pytest.mark.asyncio
async def test_valid_email_code_is_single_use_and_does_not_activate_before_phone(monkeypatch) -> None:
    challenge = make_challenge(monkeypatch)
    user = make_user()
    db = FakeSession(user, challenge)

    assert await verify_otp(db, "email", user.email, "123456") is True
    assert challenge.is_verified is True
    assert challenge.verified_at is not None
    assert user.email_verified is True
    assert user.phone_verified is False
    assert user.is_verified is False
    assert user.is_active is False

    with pytest.raises(InvalidOTPError):
        await verify_otp(FakeSession(user, challenge), "email", user.email, "123456")


@pytest.mark.asyncio
async def test_phone_verification_activates_when_email_is_already_verified(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "test-only-secret-value-that-is-long-enough")
    user = make_user()
    user.email_verified = True
    challenge = OTPChallenge(
        user_id=user.id,
        channel="whatsapp",
        purpose="phone_verification",
        otp_hash=hash_otp("654321", user.id, "phone_verification"),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        is_verified=False,
        attempts=0,
        resend_count=0,
        last_sent_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )

    await verify_otp(FakeSession(user, challenge), "whatsapp", user.phone, "654321")
    assert user.phone_verified is True
    assert user.is_verified is True
    assert user.is_active is True


@pytest.mark.asyncio
async def test_wrong_code_increments_attempts_and_is_rejected(monkeypatch) -> None:
    challenge = make_challenge(monkeypatch)
    db = FakeSession(make_user(), challenge)

    with pytest.raises(InvalidOTPError):
        await verify_otp(db, "email", "ada@example.com", "000000")

    assert challenge.attempts == 1
    assert db.commits == 1


@pytest.mark.asyncio
async def test_expired_and_attempt_exhausted_codes_are_rejected(monkeypatch) -> None:
    expired = make_challenge(
        monkeypatch,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    expired_db = FakeSession(make_user(), expired)
    with pytest.raises(InvalidOTPError):
        await verify_otp(expired_db, "email", "ada@example.com", "123456")
    assert expired.attempts == 0

    exhausted = make_challenge(monkeypatch, attempts=5)
    with pytest.raises(InvalidOTPError):
        await verify_otp(FakeSession(make_user(), exhausted), "email", "ada@example.com", "123456")


@pytest.mark.asyncio
async def test_resend_cooldown_and_limit_prevent_provider_call(monkeypatch) -> None:
    user = make_user()
    recent = make_challenge(monkeypatch, last_sent_at=datetime.now(timezone.utc))
    db = FakeSession(user, recent)
    called = False

    async def deliver(_recipient: str, _code: str) -> None:
        nonlocal called
        called = True

    assert await issue_otp(db, "email", user.email, deliver) is False
    assert called is False

    capped = make_challenge(
        monkeypatch,
        resend_count=3,
        last_sent_at=datetime.now(timezone.utc) - timedelta(minutes=2),
    )
    assert await issue_otp(FakeSession(user, capped), "email", user.email, deliver) is False
    assert called is False


@pytest.mark.asyncio
async def test_resend_after_cooldown_replaces_code_and_increments_counter(monkeypatch) -> None:
    user = make_user()
    challenge = make_challenge(
        monkeypatch,
        last_sent_at=datetime.now(timezone.utc) - timedelta(minutes=2),
    )
    db = FakeSession(user, challenge)
    sent = []

    async def deliver(_recipient: str, code: str) -> None:
        sent.append(code)

    assert await issue_otp(db, "email", user.email, deliver) is True
    assert challenge.resend_count == 1
    assert challenge.attempts == 0
    assert challenge.otp_hash != hash_otp("123456", user.id, "email_verification")
    assert otp_matches(sent[0], user.id, "email_verification", challenge.otp_hash)
    assert challenge.expires_at > datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_provider_failure_rolls_back_pending_challenge(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "test-only-secret-value-that-is-long-enough")
    db = FakeSession(make_user(), None)

    async def fail_delivery(_recipient: str, _code: str) -> None:
        raise OTPDeliveryError("provider unavailable")

    with pytest.raises(OTPDeliveryError):
        await issue_otp(db, "email", "ada@example.com", fail_delivery)

    assert db.rollbacks == 1
    assert db.commits == 0
