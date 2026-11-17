from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    BigInteger,
    Text,
    UniqueConstraint,
    false,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func

from app.database.base import Base


class User(Base):

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("phone", name="uq_users_phone"),
    )

    id = Column(Integer, primary_key=True, index=True)

    full_name = Column(String(150), nullable=False)

    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )

    phone = Column(String(20), nullable=True)

    password_hash = Column(String(255), nullable=True)

    email_verified = Column(Boolean, nullable=False, default=False, server_default=false())

    phone_verified = Column(Boolean, nullable=False, default=False, server_default=false())

    totp_enabled = Column(Boolean, nullable=False, default=False, server_default=false())

    totp_secret_encrypted = Column(Text, nullable=True)

    totp_confirmed_at = Column(DateTime(timezone=True), nullable=True)

    totp_last_used_step = Column(BigInteger, nullable=True)

    totp_failed_attempts = Column(Integer, nullable=False, default=0, server_default=text("0"))

    totp_locked_until = Column(DateTime(timezone=True), nullable=True)

    totp_recovery_codes = Column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )

    failed_login_attempts = Column(Integer, nullable=False, default=0, server_default=text("0"))

    login_locked_until = Column(DateTime(timezone=True), nullable=True)

    is_verified = Column(Boolean, default=False)

    is_active = Column(Boolean, default=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
