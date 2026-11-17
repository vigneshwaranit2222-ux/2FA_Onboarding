from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.sql import func

from app.database.base import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("ix_refresh_tokens_family_id", "family_id"),
        Index("ix_refresh_tokens_user_expires", "user_id", "expires_at"),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer,
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
            name="fk_refresh_tokens_user_id_users",
        ),
        nullable=False,
    )
    family_id = Column(String(36), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    replaced_by_token_id = Column(
        Integer,
        ForeignKey(
            "refresh_tokens.id",
            name="fk_refresh_tokens_replaced_by_token_id_refresh_tokens",
        ),
        nullable=True,
    )
