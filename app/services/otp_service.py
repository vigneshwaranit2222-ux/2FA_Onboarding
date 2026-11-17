import hashlib
import hmac
import os
import secrets
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.otp import OTPChallenge
from app.models.user import User


EMAIL_PURPOSE = "email_verification"
WHATSAPP_PURPOSE = "phone_verification"


class OTPConfigurationError(Exception):
    pass


class OTPDeliveryError(Exception):
    pass


class InvalidOTPError(Exception):
    pass


DeliveryFunction = Callable[[str, str], Awaitable[None]]


def get_otp_length() -> int:
    return _int_setting("OTP_LENGTH", 6, 4, 10)


def generate_otp(length: int | None = None) -> str:
    effective_length = length or get_otp_length()
    max_value = 10**effective_length
    return f"{secrets.randbelow(max_value):0{effective_length}d}"


def _otp_secret() -> bytes:
    secret = os.getenv("OTP_HASH_SECRET", "")
    if len(secret) < 32:
        raise OTPConfigurationError("OTP_HASH_SECRET must contain at least 32 characters")
    return secret.encode("utf-8")


def _int_setting(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise OTPConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise OTPConfigurationError(f"{name} is outside the supported range")
    return value


def get_otp_ttl_seconds() -> int:
    expire_minutes = os.getenv("OTP_EXPIRE_MINUTES")
    if expire_minutes is not None and expire_minutes.strip():
        minutes = _int_setting("OTP_EXPIRE_MINUTES", 5, 1, 60)
        return minutes * 60
    return _int_setting("OTP_TTL_SECONDS", 600, 60, 3600)


def ensure_otp_configured() -> None:
    _otp_secret()
    get_otp_length()
    get_otp_ttl_seconds()
    _int_setting("OTP_RESEND_COOLDOWN_SECONDS", 60, 0, 86400)
    _int_setting("OTP_MAX_ATTEMPTS", 5, 1, 20)
    _int_setting("OTP_MAX_RESENDS", 3, 0, 10)


def hash_otp(code: str, user_id: int, purpose: str) -> str:
    message = f"{user_id}:{purpose}:{code}".encode("utf-8")
    return hmac.new(_otp_secret(), message, hashlib.sha256).hexdigest()


def otp_matches(code: str, user_id: int, purpose: str, stored_hash: str) -> bool:
    try:
        candidate = hash_otp(code, user_id, purpose)
    except OTPConfigurationError:
        raise
    return hmac.compare_digest(candidate, stored_hash)


def _channel_details(channel: str) -> tuple[str, str]:
    if channel == "email":
        return "email_verified", EMAIL_PURPOSE
    if channel == "whatsapp":
        return "phone_verified", WHATSAPP_PURPOSE
    raise ValueError("Unsupported OTP channel")


async def issue_otp(
    db: AsyncSession,
    channel: str,
    recipient: str,
    deliver: DeliveryFunction,
) -> bool:
    """Issue an OTP; return false for unknown or already verified accounts."""
    ensure_otp_configured()
    user_field, purpose = _channel_details(channel)
    normalized_recipient = recipient.lower() if channel == "email" else recipient
    user_column = User.email if channel == "email" else User.phone
    user = await db.scalar(select(User).where(user_column == normalized_recipient))

    if user is None or getattr(user, user_field):
        return False

    now = datetime.now(timezone.utc)
    challenge = await db.scalar(
        select(OTPChallenge)
        .where(
            OTPChallenge.user_id == user.id,
            OTPChallenge.channel == channel,
            OTPChallenge.purpose == purpose,
        )
        .order_by(OTPChallenge.created_at.desc())
        .limit(1)
        .with_for_update()
    )

    if challenge is not None:
        if challenge.is_verified:
            return False
        if challenge.expires_at <= now:
            challenge = None
        else:
            cooldown = _int_setting("OTP_RESEND_COOLDOWN_SECONDS", 60, 0, 86400)
            if (now - challenge.last_sent_at).total_seconds() < cooldown:
                return False
            max_resends = _int_setting("OTP_MAX_RESENDS", 3, 0, 10)
            if challenge.resend_count >= max_resends:
                return False

    code = generate_otp()
    code_hash = hash_otp(code, user.id, purpose)

    if challenge is None:
        challenge = OTPChallenge(
            user_id=user.id,
            channel=channel,
            purpose=purpose,
            otp_hash=code_hash,
            expires_at=now + timedelta(seconds=get_otp_ttl_seconds()),
            is_verified=False,
            attempts=0,
            resend_count=0,
            last_sent_at=now,
            created_at=now,
        )
        db.add(challenge)
    else:
        challenge.otp_hash = code_hash
        challenge.expires_at = now + timedelta(seconds=get_otp_ttl_seconds())
        challenge.attempts = 0
        challenge.resend_count += 1
        challenge.last_sent_at = now

    try:
        await deliver(normalized_recipient, code)
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    return True


async def verify_otp(
    db: AsyncSession,
    channel: str,
    recipient: str,
    code: str,
) -> bool:
    """Verify the most recent challenge and update account verification state."""
    ensure_otp_configured()
    user_field, purpose = _channel_details(channel)
    normalized_recipient = recipient.lower() if channel == "email" else recipient
    user_column = User.email if channel == "email" else User.phone
    user = await db.scalar(select(User).where(user_column == normalized_recipient))
    if user is None:
        raise InvalidOTPError

    challenge = await db.scalar(
        select(OTPChallenge)
        .where(
            OTPChallenge.user_id == user.id,
            OTPChallenge.channel == channel,
            OTPChallenge.purpose == purpose,
        )
        .order_by(OTPChallenge.created_at.desc())
        .limit(1)
        .with_for_update()
    )
    now = datetime.now(timezone.utc)
    if (
        challenge is None
        or challenge.is_verified
        or challenge.expires_at <= now
        or challenge.attempts >= _int_setting("OTP_MAX_ATTEMPTS", 5, 1, 20)
    ):
        raise InvalidOTPError

    challenge.attempts += 1
    try:
        matches = otp_matches(code, user.id, purpose, challenge.otp_hash)
        if not matches:
            await db.commit()
            raise InvalidOTPError

        challenge.is_verified = True
        challenge.verified_at = now
        setattr(user, user_field, True)
        fully_verified = bool(user.email_verified and user.phone_verified)
        user.is_verified = fully_verified
        user.is_active = fully_verified
        await db.commit()
    except InvalidOTPError:
        raise
    except Exception:
        await db.rollback()
        raise

    return True
