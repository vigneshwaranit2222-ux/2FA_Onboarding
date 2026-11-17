import os
from datetime import datetime, timezone
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.models.refresh_token import RefreshToken


_bearer = HTTPBearer(auto_error=False)
_ALLOWED_ALGORITHMS = {"HS256", "HS384", "HS512"}


def get_jwt_settings() -> tuple[str, str]:
    secret = os.getenv("JWT_SECRET_KEY", "")
    algorithm = os.getenv("JWT_ALGORITHM", "HS256").strip()
    if len(secret.encode("utf-8")) < 32 or algorithm not in _ALLOWED_ALGORITHMS:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured",
        )
    return secret, algorithm


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    secret, algorithm = get_jwt_settings()
    try:
        claims = jwt.decode(
            credentials.credentials,
            secret,
            algorithms=[algorithm],
            options={"require": ["sub", "iat", "exp", "type", "sid"]},
        )
        if claims.get("type") != "access":
            raise jwt.InvalidTokenError("wrong token type")
        user_id = int(claims["sub"])
        session_id = str(UUID(claims["sid"]))
        if user_id < 1:
            raise jwt.InvalidTokenError("invalid subject")
    except (jwt.PyJWTError, TypeError, ValueError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    active_session = await db.scalar(
        select(RefreshToken.id).where(
            RefreshToken.family_id == session_id,
            RefreshToken.user_id == user.id,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
    )
    if active_session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
