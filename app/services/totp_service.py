import base64
import hashlib
import hmac
import io
import os
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken

from app.models.user import User


TOTP_CLOCK_WINDOW = 1
RECOVERY_CODE_COUNT = 10
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


class TOTPConfigurationError(Exception):
    pass


class TOTPAlreadyEnabledError(Exception):
    pass


class TOTPNotEnabledError(Exception):
    pass


class InvalidTOTPCodeError(Exception):
    pass


class TOTPAttemptLockedError(Exception):
    pass


class InvalidRecoveryCodeError(Exception):
    pass


def _fernet() -> Fernet:
    key = os.getenv("TOTP_ENCRYPTION_KEY", "").strip()
    if not key:
        raise TOTPConfigurationError("TOTP encryption is not configured")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise TOTPConfigurationError("TOTP encryption key is invalid") from exc


def encrypt_totp_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt_totp_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeEncodeError, UnicodeDecodeError) as exc:
        raise TOTPConfigurationError("Stored TOTP secret cannot be decrypted") from exc


def _issuer() -> str:
    issuer = os.getenv("TOTP_ISSUER", "Resume Onboarding").strip()
    if not issuer:
        raise TOTPConfigurationError("TOTP_ISSUER cannot be empty")
    return issuer


def begin_totp_enrollment(user: User) -> tuple[str, str]:
    if user.totp_enabled:
        raise TOTPAlreadyEnabledError

    secret = pyotp.random_base32()
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.email,
        issuer_name=_issuer(),
    )
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    image_buffer = io.BytesIO()
    image.save(image_buffer, format="PNG")
    qr_data_uri = "data:image/png;base64," + base64.b64encode(
        image_buffer.getvalue()
    ).decode("ascii")

    user.totp_secret_encrypted = encrypt_totp_secret(secret)
    user.totp_confirmed_at = None
    user.totp_last_used_step = None
    user.totp_recovery_codes = []
    return provisioning_uri, qr_data_uri


def _record_failed_attempt(user: User, now: datetime) -> None:
    attempts = int(user.totp_failed_attempts or 0) + 1
    user.totp_failed_attempts = attempts
    if attempts >= MAX_FAILED_ATTEMPTS:
        user.totp_locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)


def _check_lock(user: User, now: datetime) -> None:
    locked_until = user.totp_locked_until
    if locked_until is not None and locked_until > now:
        raise TOTPAttemptLockedError
    if locked_until is not None:
        user.totp_locked_until = None
        user.totp_failed_attempts = 0


def verify_totp_code(
    user: User,
    code: str,
    *,
    allow_pending: bool = False,
    now: datetime | None = None,
) -> int:
    now = now or datetime.now(timezone.utc)
    _check_lock(user, now)

    if user.totp_enabled and not allow_pending:
        encrypted_secret = user.totp_secret_encrypted
    elif allow_pending and not user.totp_enabled:
        encrypted_secret = user.totp_secret_encrypted
    else:
        raise TOTPNotEnabledError

    if not encrypted_secret:
        raise TOTPNotEnabledError

    secret = decrypt_totp_secret(encrypted_secret)
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    current_step = totp.timecode(now)
    accepted_step = None
    for offset in range(-TOTP_CLOCK_WINDOW, TOTP_CLOCK_WINDOW + 1):
        step = current_step + offset
        if hmac.compare_digest(totp.generate_otp(step), code):
            accepted_step = step
            break

    last_used_step = user.totp_last_used_step
    if accepted_step is None or (
        last_used_step is not None and accepted_step <= last_used_step
    ):
        _record_failed_attempt(user, now)
        raise InvalidTOTPCodeError

    user.totp_last_used_step = accepted_step
    user.totp_failed_attempts = 0
    user.totp_locked_until = None
    return accepted_step


def _hash_recovery_code(user_id: int, code: str) -> str:
    return hashlib.sha256(f"{user_id}:{code}".encode("utf-8")).hexdigest()


def _new_recovery_codes(user: User) -> list[str]:
    codes = [secrets.token_urlsafe(12) for _ in range(RECOVERY_CODE_COUNT)]
    user.totp_recovery_codes = [
        _hash_recovery_code(user.id, code) for code in codes
    ]
    return codes


def confirm_totp_enrollment(user: User, code: str) -> list[str]:
    if user.totp_enabled:
        raise TOTPAlreadyEnabledError
    step = verify_totp_code(user, code, allow_pending=True)
    user.totp_enabled = True
    user.totp_confirmed_at = datetime.now(timezone.utc)
    user.totp_last_used_step = step
    return _new_recovery_codes(user)


def consume_recovery_code(user: User, code: str) -> None:
    now = datetime.now(timezone.utc)
    _check_lock(user, now)
    stored_codes = list(user.totp_recovery_codes or [])
    candidate = _hash_recovery_code(user.id, code)
    match_index = next(
        (
            index
            for index, stored_hash in enumerate(stored_codes)
            if hmac.compare_digest(candidate, stored_hash)
        ),
        None,
    )
    if match_index is None:
        _record_failed_attempt(user, now)
        raise InvalidRecoveryCodeError
    stored_codes.pop(match_index)
    user.totp_recovery_codes = stored_codes


def disable_totp(user: User, *, code: str | None, recovery_code: str | None) -> None:
    if not user.totp_enabled:
        raise TOTPNotEnabledError
    if bool(code) == bool(recovery_code):
        raise ValueError("Exactly one TOTP or recovery code is required")
    if code:
        verify_totp_code(user, code)
    else:
        consume_recovery_code(user, recovery_code or "")

    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_confirmed_at = None
    user.totp_last_used_step = None
    user.totp_failed_attempts = 0
    user.totp_locked_until = None
    user.totp_recovery_codes = []
