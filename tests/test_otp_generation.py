import os
import secrets
import pytest

from app.services.otp_service import (
    OTPConfigurationError,
    generate_otp,
    get_otp_length,
    hash_otp,
    otp_matches,
)


def test_generate_otp_default_six_digits(monkeypatch) -> None:
    monkeypatch.delenv("OTP_LENGTH", raising=False)
    for _ in range(50):
        code = generate_otp()
        assert len(code) == 6
        assert code.isdigit()


def test_generate_otp_preserves_leading_zeros(monkeypatch) -> None:
    # Force secrets.randbelow to return numbers with leading zeros (e.g. 7 -> "000007")
    monkeypatch.setattr(secrets, "randbelow", lambda _max: 42)
    code = generate_otp()
    assert code == "000042"
    assert len(code) == 6


def test_generate_otp_configurable_length(monkeypatch) -> None:
    monkeypatch.setenv("OTP_LENGTH", "8")
    assert get_otp_length() == 8
    code = generate_otp()
    assert len(code) == 8
    assert code.isdigit()

    monkeypatch.setenv("OTP_LENGTH", "4")
    assert get_otp_length() == 4
    code = generate_otp()
    assert len(code) == 4
    assert code.isdigit()


def test_otp_length_validation_bounds(monkeypatch) -> None:
    monkeypatch.setenv("OTP_LENGTH", "3")
    with pytest.raises(OTPConfigurationError):
        get_otp_length()

    monkeypatch.setenv("OTP_LENGTH", "15")
    with pytest.raises(OTPConfigurationError):
        get_otp_length()

    monkeypatch.setenv("OTP_LENGTH", "invalid")
    with pytest.raises(OTPConfigurationError):
        get_otp_length()


def test_hash_otp_keyed_hmac_sha256(monkeypatch) -> None:
    secret = "a" * 32
    monkeypatch.setenv("OTP_HASH_SECRET", secret)

    code = "123456"
    user_id = 99
    purpose = "email_verification"

    digest1 = hash_otp(code, user_id, purpose)
    digest2 = hash_otp(code, user_id, purpose)

    assert digest1 == digest2
    assert len(digest1) == 64  # SHA-256 produces 64 hex chars
    assert code not in digest1

    # Changing secret changes hash
    monkeypatch.setenv("OTP_HASH_SECRET", "b" * 32)
    digest_different_key = hash_otp(code, user_id, purpose)
    assert digest_different_key != digest1


def test_otp_matches_constant_time_comparison(monkeypatch) -> None:
    monkeypatch.setenv("OTP_HASH_SECRET", "secret-must-be-at-least-32-chars-long")
    code = "654321"
    digest = hash_otp(code, 42, "phone_verification")

    assert otp_matches(code, 42, "phone_verification", digest) is True
    assert otp_matches("654320", 42, "phone_verification", digest) is False
    assert otp_matches(code, 43, "phone_verification", digest) is False
    assert otp_matches(code, 42, "email_verification", digest) is False

