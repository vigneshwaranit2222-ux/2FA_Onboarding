import base64
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from cryptography.fernet import Fernet

from app.models.user import User
from app.services.totp_service import (
    InvalidRecoveryCodeError,
    InvalidTOTPCodeError,
    TOTPAttemptLockedError,
    TOTPConfigurationError,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    consume_recovery_code,
    decrypt_totp_secret,
    disable_totp,
    encrypt_totp_secret,
    verify_totp_code,
)


def make_user(*, enabled: bool = False) -> User:
    return User(
        id=3,
        full_name="Ada Lovelace",
        email="ada@example.com",
        phone="+14155552671",
        password_hash="test-hash",
        email_verified=True,
        phone_verified=True,
        is_verified=True,
        is_active=True,
        totp_enabled=enabled,
        totp_secret_encrypted=None,
        totp_confirmed_at=None,
        totp_last_used_step=None,
        totp_failed_attempts=0,
        totp_locked_until=None,
        totp_recovery_codes=[],
    )


def set_encryption_key(monkeypatch) -> bytes:
    key = Fernet.generate_key()
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", key.decode("ascii"))
    return key


def test_totp_secret_is_encrypted_at_rest(monkeypatch) -> None:
    key = set_encryption_key(monkeypatch)
    secret = pyotp.random_base32()
    ciphertext = encrypt_totp_secret(secret)

    assert ciphertext != secret
    assert decrypt_totp_secret(ciphertext) == secret

    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    with pytest.raises(TOTPConfigurationError):
        decrypt_totp_secret(ciphertext)
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", key.decode("ascii"))


def test_setup_creates_qr_and_does_not_enable_totp(monkeypatch) -> None:
    set_encryption_key(monkeypatch)
    user = make_user()

    provisioning_uri, qr_data_uri = begin_totp_enrollment(user)
    secret = parse_qs(urlparse(provisioning_uri).query)["secret"][0]
    qr_bytes = base64.b64decode(qr_data_uri.split(",", 1)[1])

    assert provisioning_uri.startswith("otpauth://totp/")
    assert user.totp_secret_encrypted != secret
    assert decrypt_totp_secret(user.totp_secret_encrypted) == secret
    assert qr_data_uri.startswith("data:image/png;base64,")
    assert qr_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    assert user.totp_enabled is False


def test_current_and_neighbor_time_step_codes_are_accepted_once(monkeypatch) -> None:
    set_encryption_key(monkeypatch)
    secret = pyotp.random_base32()
    user = make_user(enabled=True)
    user.totp_secret_encrypted = encrypt_totp_secret(secret)
    now = datetime.now(timezone.utc)
    previous_step_code = pyotp.TOTP(secret).at(now - timedelta(seconds=30))

    accepted_step = verify_totp_code(user, previous_step_code, now=now)
    assert accepted_step == user.totp_last_used_step
    with pytest.raises(InvalidTOTPCodeError):
        verify_totp_code(user, previous_step_code, now=now)


def test_out_of_window_code_is_rejected_and_failed_attempt_is_recorded(monkeypatch) -> None:
    set_encryption_key(monkeypatch)
    secret = pyotp.random_base32()
    user = make_user(enabled=True)
    user.totp_secret_encrypted = encrypt_totp_secret(secret)
    now = datetime.now(timezone.utc)
    outside_window_code = pyotp.TOTP(secret).at(now + timedelta(minutes=3))

    with pytest.raises(InvalidTOTPCodeError):
        verify_totp_code(user, outside_window_code, now=now)
    assert user.totp_failed_attempts == 1


def test_failed_attempts_lock_authenticator_verification(monkeypatch) -> None:
    set_encryption_key(monkeypatch)
    secret = pyotp.random_base32()
    user = make_user(enabled=True)
    user.totp_secret_encrypted = encrypt_totp_secret(secret)
    now = datetime.now(timezone.utc)
    invalid_code = next(
        code
        for code in (f"{value:06d}" for value in range(10))
        if all(
            code != pyotp.TOTP(secret).generate_otp(pyotp.TOTP(secret).timecode(now) + offset)
            for offset in (-1, 0, 1)
        )
    )

    for _ in range(5):
        with pytest.raises(InvalidTOTPCodeError):
            verify_totp_code(user, invalid_code, now=now)
    assert user.totp_locked_until is not None
    with pytest.raises(TOTPAttemptLockedError):
        verify_totp_code(user, pyotp.TOTP(secret).now(), now=now)


def test_enrollment_returns_one_time_hashed_recovery_codes(monkeypatch) -> None:
    set_encryption_key(monkeypatch)
    user = make_user()
    begin_totp_enrollment(user)
    secret = decrypt_totp_secret(user.totp_secret_encrypted)

    recovery_codes = confirm_totp_enrollment(user, pyotp.TOTP(secret).now())

    assert user.totp_enabled is True
    assert user.totp_confirmed_at is not None
    assert len(recovery_codes) == 10
    assert len(user.totp_recovery_codes) == 10
    assert not any(code in user.totp_recovery_codes for code in recovery_codes)


def test_recovery_code_is_single_use_and_can_disable_totp(monkeypatch) -> None:
    set_encryption_key(monkeypatch)
    user = make_user()
    begin_totp_enrollment(user)
    secret = decrypt_totp_secret(user.totp_secret_encrypted)
    recovery_codes = confirm_totp_enrollment(user, pyotp.TOTP(secret).now())

    consume_recovery_code(user, recovery_codes[0])
    with pytest.raises(InvalidRecoveryCodeError):
        consume_recovery_code(user, recovery_codes[0])
    disable_totp(user, code=None, recovery_code=recovery_codes[1])
    assert user.totp_enabled is False
    assert user.totp_secret_encrypted is None
    assert user.totp_recovery_codes == []
