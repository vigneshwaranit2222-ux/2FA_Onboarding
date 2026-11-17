from collections.abc import AsyncIterator

import httpx
import pytest

from app.database.session import get_db
from app.main import app
from app.services.otp_service import InvalidOTPError, OTPConfigurationError, OTPDeliveryError


async def request_with_db(method: str, path: str, payload: dict):
    async def override_get_db() -> AsyncIterator[object]:
        yield object()

    app.dependency_overrides[get_db] = override_get_db
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            return await client.request(method, path, json=payload)
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_email_send_route_returns_generic_accepted_response(monkeypatch) -> None:
    monkeypatch.setattr("app.routers.auth.ensure_email_configured", lambda: None)
    monkeypatch.setattr("app.routers.auth.ensure_otp_configured", lambda: None)
    called = {}

    async def fake_issue(_db, channel, recipient, deliver):
        called.update(channel=channel, recipient=recipient, deliver=deliver)
        return True

    monkeypatch.setattr("app.routers.auth.issue_otp", fake_issue)
    response = await request_with_db(
        "POST",
        "/api/v1/auth/email/send-otp",
        {"email": "Ada@example.com"},
    )

    assert response.status_code == 202
    assert "ada@example.com" not in response.text
    assert called["channel"] == "email"
    assert called["recipient"] == "ada@example.com"


@pytest.mark.asyncio
async def test_provider_failure_returns_error_instead_of_success(monkeypatch) -> None:
    monkeypatch.setattr("app.routers.auth.ensure_email_configured", lambda: None)
    monkeypatch.setattr("app.routers.auth.ensure_otp_configured", lambda: None)

    async def failed_issue(*_args):
        raise OTPDeliveryError("provider rejected")

    monkeypatch.setattr("app.routers.auth.issue_otp", failed_issue)
    response = await request_with_db(
        "POST",
        "/api/v1/auth/email/send-otp",
        {"email": "ada@example.com"},
    )

    assert response.status_code == 502
    assert "OTP" not in response.text


@pytest.mark.asyncio
async def test_missing_whatsapp_configuration_returns_service_unavailable(monkeypatch) -> None:
    def not_configured():
        raise OTPConfigurationError("missing setting")

    monkeypatch.setattr("app.routers.auth.ensure_whatsapp_configured", not_configured)
    response = await request_with_db(
        "POST",
        "/api/v1/auth/whatsapp/send-otp",
        {"phone": "+1 (415) 555-2671"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "WhatsApp verification is not configured"


@pytest.mark.asyncio
async def test_invalid_or_expired_code_returns_generic_client_error(monkeypatch) -> None:
    async def invalid(*_args):
        raise InvalidOTPError

    monkeypatch.setattr("app.routers.auth.verify_otp", invalid)
    response = await request_with_db(
        "POST",
        "/api/v1/auth/email/verify-otp",
        {"email": "ada@example.com", "code": "000000"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Verification code is invalid or expired"
