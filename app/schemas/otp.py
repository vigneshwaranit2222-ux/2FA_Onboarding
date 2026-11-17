import re

from pydantic import BaseModel, EmailStr, Field, field_validator


class EmailOTPSendRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> EmailStr:
        return value.lower()


class EmailOTPVerifyRequest(EmailOTPSendRequest):
    code: str = Field(min_length=4, max_length=10, pattern=r"^\d+$")


class WhatsAppOTPSendRequest(BaseModel):
    phone: str = Field(min_length=9, max_length=24)

    @field_validator("phone")
    @classmethod
    def normalize_phone(cls, value: str) -> str:
        normalized = re.sub(r"[\s().-]", "", value)
        if not re.fullmatch(r"\+[1-9]\d{7,14}", normalized):
            raise ValueError("Phone must be a valid international number in E.164 format")
        return normalized


class WhatsAppOTPVerifyRequest(WhatsAppOTPSendRequest):
    code: str = Field(min_length=4, max_length=10, pattern=r"^\d+$")


class OTPActionResponse(BaseModel):
    success: bool = True
    message: str
    channel: str | None = None
    expires_in_seconds: int | None = None


class OTPVerificationResponse(BaseModel):
    success: bool = True
    verified: bool = True
    message: str
    email_verified: bool | None = None
    phone_verified: bool | None = None
    is_verified: bool | None = None
