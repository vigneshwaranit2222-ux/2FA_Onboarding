import httpx
import pytest
import smtplib

from app.services import email_service, whatsapp_service
from app.services.otp_service import OTPConfigurationError, OTPDeliveryError


@pytest.mark.asyncio
async def test_email_provider_uses_smtp_configuration_without_network(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "accounts@example.test")
    monkeypatch.setenv("SMTP_STARTTLS", "true")
    monkeypatch.setenv("SMTP_USE_SSL", "false")
    monkeypatch.setenv("OTP_TTL_SECONDS", "600")
    sent = []
    monkeypatch.setattr(email_service, "_send_email", lambda recipient, code, _settings: sent.append((recipient, code)))

    await email_service.send_email_otp("ada@example.test", "001234")

    assert sent == [("ada@example.test", "001234")]


@pytest.mark.asyncio
async def test_smtp_failure_is_reported_as_delivery_failure(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "accounts@example.test")
    monkeypatch.setenv("SMTP_STARTTLS", "true")
    monkeypatch.setenv("SMTP_USE_SSL", "false")

    def fail_send(_recipient, _code, _settings):
        raise smtplib.SMTPConnectError(421, b"temporarily unavailable")

    monkeypatch.setattr(email_service, "_send_email", fail_send)
    with pytest.raises(OTPDeliveryError):
        await email_service.send_email_otp("ada@example.test", "001234")


@pytest.mark.asyncio
async def test_whatsapp_provider_submits_configured_auth_template(monkeypatch) -> None:
    monkeypatch.setenv("WHATSAPP_API_TOKEN", "test-token")
    monkeypatch.setenv("WHATSAPP_PHONE_NUMBER_ID", "1234567890")
    monkeypatch.setenv("WHATSAPP_OTP_TEMPLATE", "account_verification")
    monkeypatch.setenv("WHATSAPP_API_VERSION", "v99.0")
    captured = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"messages": [{"id": "provider-message-id"}]}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def post(self, url, *, headers, json):
            captured.update(url=url, headers=headers, payload=json)
            return Response()

    monkeypatch.setattr(whatsapp_service.httpx, "AsyncClient", lambda **_kwargs: Client())
    await whatsapp_service.send_whatsapp_otp("+14155552671", "001234")

    assert captured["url"].endswith("/v99.0/1234567890/messages")
    assert captured["headers"]["Authorization"] == "Bearer test-token"
    assert captured["payload"]["to"] == "+14155552671"
    assert captured["payload"]["template"]["name"] == "account_verification"
    assert captured["payload"]["template"]["components"][0]["parameters"][0]["text"] == "001234"


@pytest.mark.asyncio
async def test_whatsapp_provider_failure_is_not_reported_as_accepted(monkeypatch) -> None:
    monkeypatch.setenv("WHATSAPP_API_TOKEN", "test-token")
    monkeypatch.setenv("WHATSAPP_PHONE_NUMBER_ID", "1234567890")
    monkeypatch.setenv("WHATSAPP_OTP_TEMPLATE", "account_verification")
    monkeypatch.setenv("WHATSAPP_API_VERSION", "v99.0")

    class Response:
        def raise_for_status(self) -> None:
            request = httpx.Request("POST", "https://graph.facebook.com")
            response = httpx.Response(400, request=request)
            raise httpx.HTTPStatusError("rejected", request=request, response=response)

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(whatsapp_service.httpx, "AsyncClient", lambda **_kwargs: Client())
    with pytest.raises(OTPDeliveryError):
        await whatsapp_service.send_whatsapp_otp("+14155552671", "001234")


def test_missing_provider_configuration_fails_clearly(monkeypatch) -> None:
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_FROM_EMAIL", raising=False)
    with pytest.raises(OTPConfigurationError):
        email_service.ensure_email_configured()

    monkeypatch.delenv("WHATSAPP_API_TOKEN", raising=False)
    monkeypatch.delenv("WHATSAPP_PHONE_NUMBER_ID", raising=False)
    monkeypatch.delenv("WHATSAPP_OTP_TEMPLATE", raising=False)
    monkeypatch.delenv("WHATSAPP_API_VERSION", raising=False)
    with pytest.raises(OTPConfigurationError):
        whatsapp_service.ensure_whatsapp_configured()
