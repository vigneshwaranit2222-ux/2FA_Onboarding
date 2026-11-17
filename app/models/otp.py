from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    text,
)
from sqlalchemy.sql import func

from app.database.base import Base


class OTPChallenge(Base):

    __tablename__ = "otp_challenges"
    __table_args__ = (
        Index(
            "ix_otp_user_channel_purpose_created",
            "user_id",
            "channel",
            "purpose",
            "created_at",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    channel = Column(String(30), nullable=False)

    purpose = Column(String(50), nullable=False)

    otp_hash = Column(String(255), nullable=False)

    expires_at = Column(DateTime(timezone=True), nullable=False)

    is_verified = Column(Boolean, default=False)

    attempts = Column(Integer, nullable=False, default=0, server_default=text("0"))

    resend_count = Column(Integer, nullable=False, default=0, server_default=text("0"))

    last_sent_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    verified_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
