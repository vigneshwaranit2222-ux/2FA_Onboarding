from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import pytest
import smtplib

from app.models.otp import OTPChallenge
from app.models.user import User
from app.services import email_service
from app.services.email_service import _send_email, _smtp_settings, send_email_otp
from app.services.otp_service import (
    InvalidOTPError,
    OTPConfigurationError,
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


def make_unverified_user() -> User:
    return User(
        id=101,
        full_name="Grace Hopper",
        email="grace@example.com",
        phone="+14155552672",
        password_hash="mock-argon2-hash",
        email_verified=False,
        phone_verified=False,
        is_verified=False,
        is_active=False,
    )


@pytest.mark.asyncio
async def test_email_otp_issue_success(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_unverified_user()
    db = FakeSession(user, None)
    delivered = []

    async def mock_deliver(recipient: str, code: str) -> None:
        delivered.append((recipient, code))

    success = await issue_otp(db, "email", user.email, mock_deliver)
    assert success is True
    assert len(delivered) == 1
    assert delivered[0][0] == "grace@example.com"
    assert len(delivered[0][1]) == 6

    challenge = db.added[0]
    assert challenge.user_id == 101
    assert challenge.channel == "email"
    assert challenge.purpose == "email_verification"
    assert challenge.is_verified is False
    assert challenge.attempts == 0
    assert challenge.resend_count == 0
    assert challenge.otp_hash != delivered[0][1]


@pytest.mark.asyncio
async def test_email_otp_verify_success(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_unverified_user()
    now = datetime.now(timezone.utc)
    challenge = OTPChallenge(
        id=1,
        user_id=user.id,
        channel="email",
        purpose="email_verification",
        otp_hash=hash_otp("112233", user.id, "email_verification"),
        expires_at=now + timedelta(minutes=5),
        is_verified=False,
        attempts=0,
        resend_count=0,
        last_sent_at=now,
        created_at=now,
    )
    db = FakeSession(user, challenge)

    result = await verify_otp(db, "email", user.email, "112233")
    assert result is True
    assert challenge.is_verified is True
    assert challenge.verified_at is not None
    assert user.email_verified is True
    # Account should NOT be fully active until phone is also verified
    assert user.phone_verified is False
    assert user.is_verified is False
    assert user.is_active is False
    assert db.commits == 1


def test_email_template_contains_plaintext_and_html(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    captured_messages = []

    class MockSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def starttls(self, *args, **kwargs):
            pass

        def login(self, *args, **kwargs):
            pass

        def send_message(self, msg: EmailMessage):
            captured_messages.append(msg)
            return {}

    monkeypatch.setattr(smtplib, "SMTP", MockSMTP)

    settings = {
        "host": "smtp.example.com",
        "port": 587,
        "sender": "noreply@example.com",
        "username": "",
        "password": "",
        "starttls": True,
        "ssl": False,
        "timeout": 10,
    }

    _send_email("grace@example.com", "987654", settings)
    assert len(captured_messages) == 1
    msg = captured_messages[0]

    assert msg["To"] == "grace@example.com"
    assert msg["From"] == "noreply@example.com"
    assert "account verification code" in msg["Subject"].lower()

    # Verify both plain text and HTML payloads exist
    parts = list(msg.iter_parts()) if msg.is_multipart() else [msg]
    content_types = [p.get_content_type() for p in parts]
    assert "text/plain" in content_types
    assert "text/html" in content_types

    body_text = msg.get_body(preferencelist=("plain",)).get_content()
    assert "987654" in body_text

    body_html = msg.get_body(preferencelist=("html",)).get_content()
    assert "987654" in body_html
    assert "<html" in body_html.lower()


@pytest.mark.asyncio
async def test_email_delivery_failure_rolls_back_db(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "super-secret-key-at-least-32-chars-long")
    user = make_unverified_user()
    db = FakeSession(user, None)

    async def failing_delivery(recipient: str, code: str) -> None:
        raise OTPDeliveryError("SMTP server refused connection")

    with pytest.raises(OTPDeliveryError):
        await issue_otp(db, "email", user.email, failing_delivery)

    assert db.rollbacks == 1
    assert db.commits == 0

