from datetime import datetime, timedelta, timezone
import pytest

from app.models.otp import OTPChallenge
from app.models.user import User
from app.services import whatsapp_service
from app.services.whatsapp_service import (
    MetaWhatsAppCloudProvider,
    MockWhatsAppProvider,
    get_whatsapp_provider,
    send_whatsapp_otp,
)
from app.services.otp_service import (
    InvalidOTPError,
    OTPDeliveryError,
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


def make_user_for_phone() -> User:
    return User(
        id=202,
        full_name="Katherine Johnson",
        email="katherine@example.com",
        phone="+14155552673",
        password_hash="mock-argon2-hash",
        email_verified=True,  # Assume email is verified first
        phone_verified=False,
        is_verified=False,
        is_active=False,
    )


@pytest.mark.asyncio
async def test_mock_whatsapp_provider_in_memory(monkeypatch) -> None:
    monkeypatch.setenv("WHATSAPP_PROVIDER", "mock")
    provider = get_whatsapp_provider()
    assert isinstance(provider, MockWhatsAppProvider)

    await provider.send_otp("+14155552673", "554433")
    assert provider.sent_messages == [("+14155552673", "554433")]


@pytest.mark.asyncio
async def test_whatsapp_otp_issue_success(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_user_for_phone()
    db = FakeSession(user, None)
    delivered = []

    async def mock_deliver(recipient: str, code: str) -> None:
        delivered.append((recipient, code))

    success = await issue_otp(db, "whatsapp", user.phone, mock_deliver)
    assert success is True
    assert len(delivered) == 1
    assert delivered[0][0] == "+14155552673"
    assert len(delivered[0][1]) == 6

    challenge = db.added[0]
    assert challenge.user_id == 202
    assert challenge.channel == "whatsapp"
    assert challenge.purpose == "phone_verification"
    assert challenge.is_verified is False
    assert challenge.otp_hash != delivered[0][1]


@pytest.mark.asyncio
async def test_whatsapp_otp_verify_activates_account_when_email_verified(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_user_for_phone()
    now = datetime.now(timezone.utc)
    challenge = OTPChallenge(
        id=2,
        user_id=user.id,
        channel="whatsapp",
        purpose="phone_verification",
        otp_hash=hash_otp("667788", user.id, "phone_verification"),
        expires_at=now + timedelta(minutes=5),
        is_verified=False,
        attempts=0,
        resend_count=0,
        last_sent_at=now,
        created_at=now,
    )
    db = FakeSession(user, challenge)

    result = await verify_otp(db, "whatsapp", user.phone, "667788")
    assert result is True
    assert challenge.is_verified is True
    assert user.phone_verified is True
    # Since email was already verified, account is now fully verified & active
    assert user.email_verified is True
    assert user.is_verified is True
    assert user.is_active is True
    assert db.commits == 1


@pytest.mark.asyncio
async def test_whatsapp_provider_failure_rolls_back_db(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_user_for_phone()
    db = FakeSession(user, None)

    async def failing_deliver(recipient: str, code: str) -> None:
        raise OTPDeliveryError("Meta WhatsApp Cloud API returned 500")

    with pytest.raises(OTPDeliveryError):
        await issue_otp(db, "whatsapp", user.phone, failing_deliver)

    assert db.rollbacks == 1
    assert db.commits == 0

