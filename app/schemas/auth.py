import re
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)


class RegistrationRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    phone: str = Field(min_length=9, max_length=24)
    password: SecretStr
    confirm_password: SecretStr

    @field_validator("full_name")
    @classmethod
    def normalize_full_name(cls, value: str) -> str:
        value = " ".join(value.split())
        if len(value) < 2:
            raise ValueError("Full name must contain at least two characters")
        return value

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> EmailStr:
        return value.lower()

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        normalized = re.sub(r"[\s().-]", "", value)
        if not re.fullmatch(r"\+[1-9]\d{7,14}", normalized):
            raise ValueError("Phone must be a valid international number in E.164 format")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: SecretStr) -> SecretStr:
        password = value.get_secret_value()
        if len(password) < 12 or len(password) > 128:
            raise ValueError("Password must be between 12 and 128 characters")
        if not any(char.islower() for char in password):
            raise ValueError("Password must include a lowercase letter")
        if not any(char.isupper() for char in password):
            raise ValueError("Password must include an uppercase letter")
        if not any(char.isdigit() for char in password):
            raise ValueError("Password must include a number")
        if not any(not char.isalnum() for char in password):
            raise ValueError("Password must include a symbol")
        return value

    @model_validator(mode="after")
    def passwords_must_match(self) -> Self:
        if self.password.get_secret_value() != self.confirm_password.get_secret_value():
            raise ValueError("Password and confirmation do not match")
        return self


class RegisteredUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    full_name: str
    email: EmailStr
    phone: str | None
    is_verified: bool
    is_active: bool


class RegistrationResponse(BaseModel):
    user: RegisteredUser
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: SecretStr
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")
    recovery_code: str | None = Field(default=None, min_length=12, max_length=64)

    @field_validator("email")
    @classmethod
    def normalize_login_email(cls, value: EmailStr) -> EmailStr:
        return value.lower()

    @model_validator(mode="after")
    def one_mfa_code_at_most(self) -> Self:
        if self.totp_code and self.recovery_code:
            raise ValueError("Provide a TOTP code or recovery code, not both")
        return self


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str
    refresh_expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: SecretStr


class LogoutRequest(BaseModel):
    refresh_token: SecretStr


class LogoutResponse(BaseModel):
    message: str
