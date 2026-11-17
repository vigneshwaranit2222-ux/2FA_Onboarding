import asyncio
import os
import smtplib
import ssl
from email.message import EmailMessage

from app.services.otp_service import (
    OTPConfigurationError,
    OTPDeliveryError,
    get_otp_ttl_seconds,
)


def _smtp_settings() -> dict[str, str | int | bool]:
    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM_EMAIL", "").strip()
    if not host or not sender:
        raise OTPConfigurationError("Email OTP delivery is not configured")

    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    if bool(username) != bool(password):
        raise OTPConfigurationError("Both SMTP_USERNAME and SMTP_PASSWORD must be configured")

    try:
        port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError as exc:
        raise OTPConfigurationError("SMTP_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise OTPConfigurationError("SMTP_PORT is outside the supported range")

    try:
        timeout = int(os.getenv("SMTP_TIMEOUT", "10"))
    except ValueError as exc:
        raise OTPConfigurationError("SMTP_TIMEOUT must be an integer") from exc
    if not 1 <= timeout <= 120:
        raise OTPConfigurationError("SMTP_TIMEOUT is outside the supported range")

    use_starttls = os.getenv("SMTP_STARTTLS", "true").strip().lower() in {"1", "true", "yes"}
    use_ssl = os.getenv("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes"}
    if use_starttls == use_ssl:
        raise OTPConfigurationError(
            "Configure exactly one SMTP transport mode: STARTTLS or implicit SSL"
        )
    return {
        "host": host,
        "port": port,
        "sender": sender,
        "username": username,
        "password": password,
        "starttls": use_starttls,
        "ssl": use_ssl,
        "timeout": timeout,
    }


def ensure_email_configured() -> None:
    _smtp_settings()


def _send_email(recipient: str, code: str, settings: dict[str, str | int | bool]) -> None:
    ttl_minutes = max(1, get_otp_ttl_seconds() // 60)
    message = EmailMessage()
    message["Subject"] = "Your account verification code"
    message["From"] = str(settings["sender"])
    message["To"] = recipient

    # Plain text fallback
    message.set_content(
        f"Your verification code is {code}. It expires in "
        f"{ttl_minutes} minutes. "
        "If you did not request this code, you can ignore this email."
    )

    # Rich HTML template
    html_content = f"""\
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1a202c; margin: 0; padding: 20px;">
  <div style="max-width: 560px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 8px; padding: 32px; background-color: #ffffff;">
    <h2 style="color: #2b6cb0; margin-top: 0; font-size: 22px;">Verify Your Account</h2>
    <p style="font-size: 15px; color: #4a5568;">Please use the one-time verification code below to verify your email address:</p>
    <div style="font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #1a202c; text-align: center; padding: 18px 24px; background-color: #f7fafc; border: 1px dashed #cbd5e0; border-radius: 6px; margin: 24px 0;">
      {code}
    </div>
    <p style="font-size: 14px; color: #718096;">
      This code is single-use and will expire in <strong>{ttl_minutes} minutes</strong>.
    </p>
    <hr style="border: none; border-top: 1px solid #edf2f7; margin: 28px 0 16px 0;" />
    <p style="font-size: 12px; color: #a0aec0; margin: 0;">
      If you did not request this code, no action is needed. Do not share this code with anyone.
    </p>
  </div>
</body>
</html>
"""
    message.add_alternative(html_content, subtype="html")

    timeout_seconds = int(settings.get("timeout", 10))
    try:
        if bool(settings["ssl"]):
            smtp_client = smtplib.SMTP_SSL(
                str(settings["host"]),
                int(settings["port"]),
                timeout=timeout_seconds,
                context=ssl.create_default_context(),
            )
        else:
            smtp_client = smtplib.SMTP(
                str(settings["host"]), int(settings["port"]), timeout=timeout_seconds
            )
        with smtp_client as smtp:
            if bool(settings["starttls"]):
                smtp.starttls(context=ssl.create_default_context())
            if settings["username"]:
                smtp.login(str(settings["username"]), str(settings["password"]))
            refused = smtp.send_message(message)
            if refused:
                raise OTPDeliveryError("SMTP server refused the recipient")
    except OTPDeliveryError:
        raise
    except (OSError, smtplib.SMTPException) as exc:
        raise OTPDeliveryError("Email provider rejected the message") from exc


async def send_email_otp(recipient: str, code: str) -> None:
    settings = _smtp_settings()
    try:
        await asyncio.to_thread(_send_email, recipient, code, settings)
    except (OSError, smtplib.SMTPException) as exc:
        raise OTPDeliveryError("Email provider rejected the message") from exc
