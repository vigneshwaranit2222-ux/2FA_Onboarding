from datetime import datetime
import re

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

from app.schemas.auth import RegisteredUser


class UserProfile(RegisteredUser):
    email_verified: bool
    phone_verified: bool
    totp_enabled: bool


class UserProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str | None = Field(default=None, min_length=2, max_length=150)
    phone: str | None = Field(default=None, min_length=9, max_length=24)

    @field_validator("full_name")
    @classmethod
    def normalize_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = " ".join(value.split())
        if len(normalized) < 2:
            raise ValueError("Full name must contain at least two characters")
        return normalized

    @field_validator("phone")
    @classmethod
    def normalize_phone(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = re.sub(r"[\s().-]", "", value)
        if not re.fullmatch(r"\+[1-9]\d{7,14}", normalized):
            raise ValueError("Phone must be a valid international number in E.164 format")
        return normalized

    @model_validator(mode="after")
    def require_profile_change(self):
        if self.full_name is None and self.phone is None:
            raise ValueError("Provide at least one profile field to update")
        return self


class ResumeItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    file_name: str
    created_at: datetime | None
    extracted_data: dict | None


class ResumeDetail(ResumeItem):
    extracted_text: str | None


class ResumeExtractedDataUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str | None = Field(default=None, min_length=2, max_length=150)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, min_length=9, max_length=24)
    skills: list[str] | None = Field(default=None, max_length=50)
    experience: str | None = Field(default=None, max_length=100)

    @field_validator("full_name")
    @classmethod
    def normalize_candidate_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = " ".join(value.split())
        if len(normalized) < 2:
            raise ValueError("Name must contain at least two characters")
        return normalized

    @field_validator("email")
    @classmethod
    def normalize_candidate_email(cls, value: EmailStr | None) -> EmailStr | None:
        return value.lower() if value is not None else None

    @field_validator("phone")
    @classmethod
    def normalize_candidate_phone(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = re.sub(r"[\s().-]", "", value)
        if not re.fullmatch(r"\+[1-9]\d{7,14}", normalized):
            raise ValueError("Phone must be a valid international number in E.164 format")
        return normalized

    @field_validator("skills")
    @classmethod
    def normalize_skills(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        normalized = [skill.strip() for skill in value]
        if any(not skill or len(skill) > 50 for skill in normalized):
            raise ValueError("Each skill must contain between 1 and 50 characters")
        return normalized

    @model_validator(mode="after")
    def require_a_correction(self):
        if not self.model_fields_set:
            raise ValueError("Provide at least one extracted field to update")
        return self
