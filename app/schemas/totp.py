from typing import Self

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator


class TOTPSetupResponse(BaseModel):
    provisioning_uri: str
    qr_code_data_uri: str
    message: str


class TOTPCodeRequest(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class TOTPEnrollmentResponse(BaseModel):
    totp_enabled: bool
    recovery_codes: list[str]
    message: str


class TOTPDisableRequest(BaseModel):
    current_password: SecretStr
    code: str | None = Field(default=None, pattern=r"^\d{6}$")
    recovery_code: str | None = Field(default=None, min_length=12, max_length=64)

    @field_validator("recovery_code")
    @classmethod
    def normalize_recovery_code(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None

    @model_validator(mode="after")
    def exactly_one_factor_code(self) -> Self:
        if bool(self.code) == bool(self.recovery_code):
            raise ValueError("Provide exactly one TOTP code or recovery code")
        return self


class TOTPDisableResponse(BaseModel):
    totp_enabled: bool
    message: str
