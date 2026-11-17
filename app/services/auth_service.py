import asyncio
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.schemas.auth import LoginRequest
from app.services.password_service import hash_password, verify_password
from app.services.totp_service import (
    InvalidRecoveryCodeError,
    InvalidTOTPCodeError,
    TOTPAttemptLockedError,
    consume_recovery_code,
    verify_totp_code,
)
from app.services.token_service import TokenPair, create_token_pair


MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15


class InvalidCredentialsError(Exception):
    pass


async def authenticate_user(db: AsyncSession, request: LoginRequest) -> TokenPair:
    now = datetime.now(timezone.utc)
    user = await db.scalar(
        select(User)
        .where(User.email == str(request.email))
        .with_for_update()
    )

    if user is None:
        await asyncio.to_thread(hash_password, secrets.token_urlsafe(32))
        raise InvalidCredentialsError

    locked_until = user.login_locked_until
    if locked_until is not None and locked_until > now:
        await asyncio.to_thread(hash_password, secrets.token_urlsafe(32))
        raise InvalidCredentialsError
    if locked_until is not None:
        user.login_locked_until = None
        user.failed_login_attempts = 0

    password_ok = await asyncio.to_thread(
        verify_password,
        request.password.get_secret_value(),
        user.password_hash,
    )
    if not password_ok:
        user.failed_login_attempts = int(user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            user.login_locked_until = now + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
        await db.commit()
        raise InvalidCredentialsError

    if not (
        user.is_active
        and user.is_verified
        and user.email_verified
        and user.phone_verified
    ):
        raise InvalidCredentialsError

    if user.totp_enabled:
        if bool(request.totp_code) == bool(request.recovery_code):
            raise InvalidCredentialsError
        try:
            if request.totp_code:
                verify_totp_code(user, request.totp_code)
            else:
                consume_recovery_code(user, request.recovery_code or "")
        except (InvalidTOTPCodeError, InvalidRecoveryCodeError) as exc:
            await db.commit()
            raise InvalidCredentialsError from exc
        except TOTPAttemptLockedError as exc:
            raise InvalidCredentialsError from exc
    elif request.totp_code or request.recovery_code:
        raise InvalidCredentialsError

    user.failed_login_attempts = 0
    user.login_locked_until = None
    try:
        token_pair = await create_token_pair(db, user, now=now)
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    return token_pair
