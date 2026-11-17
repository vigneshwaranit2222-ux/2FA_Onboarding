"""Add registration verification, TOTP, and refresh-token persistence.

The existing Day 1 tables and records are preserved. Legacy OTP rows receive
best-effort purpose/timestamp values based on their existing channel and
created_at fields.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0002_auth"
down_revision = "0001_day1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("email_verified", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "users",
        sa.Column("phone_verified", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "users",
        sa.Column("totp_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("users", sa.Column("totp_secret_encrypted", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("totp_confirmed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("totp_last_used_step", sa.BigInteger(), nullable=True))
    op.add_column(
        "users",
        sa.Column("totp_failed_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("users", sa.Column("totp_locked_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "totp_recovery_codes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "users",
        sa.Column("failed_login_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("users", sa.Column("login_locked_until", sa.DateTime(timezone=True), nullable=True))
    op.create_unique_constraint("uq_users_phone", "users", ["phone"])

    op.add_column("otp_challenges", sa.Column("purpose", sa.String(length=50), nullable=True))
    op.add_column(
        "otp_challenges",
        sa.Column("resend_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("otp_challenges", sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("otp_challenges", sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))

    op.execute(
        """
        UPDATE otp_challenges
        SET purpose = CASE
            WHEN channel = 'email' THEN 'email_verification'
            WHEN channel = 'whatsapp' THEN 'phone_verification'
            ELSE 'legacy'
        END
        WHERE purpose IS NULL
        """
    )
    op.execute(
        "UPDATE otp_challenges SET last_sent_at = COALESCE(created_at, now()) WHERE last_sent_at IS NULL"
    )
    op.execute(
        "UPDATE otp_challenges SET verified_at = COALESCE(created_at, now()) "
        "WHERE is_verified IS TRUE AND verified_at IS NULL"
    )
    op.execute("UPDATE otp_challenges SET attempts = 0 WHERE attempts IS NULL")
    op.alter_column("otp_challenges", "purpose", existing_type=sa.String(length=50), nullable=False)
    op.alter_column(
        "otp_challenges",
        "attempts",
        existing_type=sa.Integer(),
        server_default=sa.text("0"),
        nullable=False,
    )
    op.alter_column(
        "otp_challenges",
        "last_sent_at",
        existing_type=sa.DateTime(timezone=True),
        server_default=sa.text("now()"),
        nullable=False,
    )
    op.create_index(
        "ix_otp_user_channel_purpose_created",
        "otp_challenges",
        ["user_id", "channel", "purpose", "created_at"],
        unique=False,
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("family_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_token_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["replaced_by_token_id"],
            ["refresh_tokens.id"],
            name="fk_refresh_tokens_replaced_by_token_id_refresh_tokens",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_refresh_tokens_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"], unique=True)
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"], unique=False)
    op.create_index(
        "ix_refresh_tokens_user_expires",
        "refresh_tokens",
        ["user_id", "expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_user_expires", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_token_hash", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")

    op.drop_index("ix_otp_user_channel_purpose_created", table_name="otp_challenges")
    op.drop_column("otp_challenges", "verified_at")
    op.drop_column("otp_challenges", "last_sent_at")
    op.drop_column("otp_challenges", "resend_count")
    op.drop_column("otp_challenges", "purpose")
    op.alter_column(
        "otp_challenges",
        "attempts",
        existing_type=sa.Integer(),
        server_default=None,
        nullable=True,
    )

    op.drop_constraint("uq_users_phone", "users", type_="unique")
    op.drop_column("users", "login_locked_until")
    op.drop_column("users", "failed_login_attempts")
    op.drop_column("users", "totp_recovery_codes")
    op.drop_column("users", "totp_locked_until")
    op.drop_column("users", "totp_failed_attempts")
    op.drop_column("users", "totp_last_used_step")
    op.drop_column("users", "totp_confirmed_at")
    op.drop_column("users", "totp_secret_encrypted")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "phone_verified")
    op.drop_column("users", "email_verified")
