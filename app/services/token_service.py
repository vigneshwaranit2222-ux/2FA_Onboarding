import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_jwt_settings
from app.models.refresh_token import RefreshToken
from app.models.user import User


class TokenConfigurationError(Exception):
    pass


class InvalidRefreshTokenError(Exception):
    pass


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_in: int
    refresh_expires_in: int
    family_id: str

    def response(self) -> dict[str, str | int]:
        return {
            "access_token": self.access_token,
            "token_type": "bearer",
            "expires_in": self.access_expires_in,
            "refresh_token": self.refresh_token,
            "refresh_expires_in": self.refresh_expires_in,
        }


def _lifetime(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise TokenConfigurationError(f"{name} must be an integer") from exc
    if not low <= value <= high:
        raise TokenConfigurationError(f"{name} is outside the supported range")
    return value


def _refresh_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_token_pair(
    db: AsyncSession,
    user: User,
    *,
    family_id: str | None = None,
    now: datetime | None = None,
) -> TokenPair:
    try:
        secret, algorithm = get_jwt_settings()
        access_minutes = _lifetime("ACCESS_TOKEN_EXPIRE_MINUTES", 15, 1, 1440)
        refresh_days = _lifetime("REFRESH_TOKEN_EXPIRE_DAYS", 7, 1, 90)
    except Exception as exc:
        raise TokenConfigurationError("Token configuration is invalid") from exc

    now = now or datetime.now(timezone.utc)
    family_id = family_id or str(uuid4())
    access_expiry = now + timedelta(minutes=access_minutes)
    refresh_expiry = now + timedelta(days=refresh_days)
    access_token = jwt.encode(
        {
            "sub": str(user.id),
            "sid": family_id,
            "iat": now,
            "exp": access_expiry,
            "type": "access",
            "jti": uuid4().hex,
        },
        secret,
        algorithm=algorithm,
    )
    refresh_token = secrets.token_urlsafe(48)
    db.add(
        RefreshToken(
            user_id=user.id,
            family_id=family_id,
            token_hash=_refresh_hash(refresh_token),
            expires_at=refresh_expiry,
            created_at=now,
        )
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_in=access_minutes * 60,
        refresh_expires_in=refresh_days * 86400,
        family_id=family_id,
    )
async def rotate_refresh_token(db: AsyncSession, raw_token: str) -> TokenPair:
    now = datetime.now(timezone.utc)
    old = await db.scalar(
        select(RefreshToken)
        .where(RefreshToken.token_hash == _refresh_hash(raw_token))
        .with_for_update()
    )
    if old is None:
        raise InvalidRefreshTokenError

    if old.revoked_at is not None:
        await db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.family_id == old.family_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        await db.commit()
        raise InvalidRefreshTokenError

    if old.expires_at <= now:
        old.revoked_at = now
        await db.commit()
        raise InvalidRefreshTokenError

    user = await db.scalar(select(User).where(User.id == old.user_id).with_for_update())
    if user is None or not user.is_active or not user.is_verified:
        await db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.family_id == old.family_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        await db.commit()
        raise InvalidRefreshTokenError

    try:
        pair = await create_token_pair(db, user, family_id=old.family_id, now=now)
        await db.flush()
        new_row = await db.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == _refresh_hash(pair.refresh_token)
            )
        )
        old.revoked_at = now
        old.replaced_by_token_id = new_row.id
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    return pair


async def revoke_refresh_token(
    db: AsyncSession,
    user_id: int,
    raw_token: str,
) -> bool:
    now = datetime.now(timezone.utc)
    row = await db.scalar(
        select(RefreshToken)
        .where(
            RefreshToken.user_id == user_id,
            RefreshToken.token_hash == _refresh_hash(raw_token),
        )
        .with_for_update()
    )
    if row is None:
        return False
    try:
        if row.revoked_at is not None:
            await db.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.family_id == row.family_id,
                    RefreshToken.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            await db.commit()
            return True
        await db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.family_id == row.family_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    return True
