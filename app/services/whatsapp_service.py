import os
import re
from typing import Protocol

import httpx

from app.services.otp_service import OTPConfigurationError, OTPDeliveryError


class WhatsAppOTPProvider(Protocol):
    async def send_otp(self, recipient: str, code: str) -> None: ...


def _whatsapp_timeout() -> int:
    try:
        timeout = int(os.getenv("WHATSAPP_TIMEOUT", "10"))
    except ValueError as exc:
        raise OTPConfigurationError("WHATSAPP_TIMEOUT must be an integer") from exc
    if not 1 <= timeout <= 120:
        raise OTPConfigurationError("WHATSAPP_TIMEOUT is outside the supported range")
    return timeout


def _whatsapp_settings() -> tuple[str, str, str, str, str]:
    token = (os.getenv("WHATSAPP_API_TOKEN") or os.getenv("WHATSAPP_API_KEY") or "").strip()
    phone_number_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
    template_name = os.getenv("WHATSAPP_OTP_TEMPLATE", "").strip()
    api_version = os.getenv("WHATSAPP_API_VERSION", "").strip()
    language = os.getenv("WHATSAPP_TEMPLATE_LANGUAGE", "en").strip()
    _whatsapp_timeout()
    if not all((token, phone_number_id, template_name, api_version, language)):
        raise OTPConfigurationError("WhatsApp OTP delivery is not configured")
    if not re.fullmatch(r"v\d+\.\d+", api_version):
        raise OTPConfigurationError("WHATSAPP_API_VERSION must be a version such as vXX.X")
    if not phone_number_id.isdigit():
        raise OTPConfigurationError("WHATSAPP_PHONE_NUMBER_ID must be numeric")
    if not re.fullmatch(r"[A-Za-z0-9_]+", template_name):
        raise OTPConfigurationError("WHATSAPP_OTP_TEMPLATE has invalid characters")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", language):
        raise OTPConfigurationError("WHATSAPP_TEMPLATE_LANGUAGE has invalid characters")
    return token, phone_number_id, template_name, api_version, language


def ensure_whatsapp_configured() -> None:
    provider_type = os.getenv("WHATSAPP_PROVIDER", "meta").strip().lower()
    if provider_type == "mock":
        return
    _whatsapp_settings()


class MockWhatsAppProvider:
    """Mock WhatsApp provider for automated tests and offline verification."""

    def __init__(self) -> None:
        self.sent_messages: list[tuple[str, str]] = []

    async def send_otp(self, recipient: str, code: str) -> None:
        self.sent_messages.append((recipient, code))


class MetaWhatsAppCloudProvider:
    async def send_otp(self, recipient: str, code: str) -> None:
        await self._send_template(recipient, code)

    async def _send_template(self, recipient: str, code: str) -> None:
        token, phone_number_id, template_name, api_version, language = _whatsapp_settings()
        timeout = _whatsapp_timeout()
        base_url = os.getenv("WHATSAPP_API_URL", "").strip()
        if base_url:
            url = f"{base_url.rstrip('/')}/{api_version}/{phone_number_id}/messages"
        else:
            url = f"https://graph.facebook.com/{api_version}/{phone_number_id}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": recipient,
            "type": "template",
            "template": {
                "name": template_name,
                "language": {"code": language},
                "components": [
                    {
                        "type": "body",
                        "parameters": [{"type": "text", "text": code}],
                    }
                ],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                if (
                    not isinstance(data, dict)
                    or not isinstance(data.get("messages"), list)
                    or not data["messages"]
                    or not isinstance(data["messages"][0], dict)
                    or not data["messages"][0].get("id")
                ):
                    raise OTPDeliveryError("WhatsApp provider did not accept the message")
        except OTPDeliveryError:
            raise
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            raise OTPDeliveryError("WhatsApp provider rejected the message") from exc


def get_whatsapp_provider() -> WhatsAppOTPProvider:
    provider_type = os.getenv("WHATSAPP_PROVIDER", "meta").strip().lower()
    if provider_type == "mock":
        return MockWhatsAppProvider()
    return MetaWhatsAppCloudProvider()


async def send_whatsapp_otp(recipient: str, code: str) -> None:
    provider: WhatsAppOTPProvider = get_whatsapp_provider()
    await provider.send_otp(recipient, code)
