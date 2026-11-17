import asyncio

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.schemas.auth import RegistrationRequest
from app.services.password_service import hash_password


class DuplicateRegistrationError(Exception):
    """Raised when an email address or phone number is already registered."""


async def register_user(
    db: AsyncSession,
    registration: RegistrationRequest,
) -> User:
    email = str(registration.email)
    phone = registration.phone

    existing_user = await db.scalar(
        select(User.id).where(or_(User.email == email, User.phone == phone))
    )
    if existing_user is not None:
        raise DuplicateRegistrationError

    user = User(
        full_name=registration.full_name,
        email=email,
        phone=phone,
        password_hash=await asyncio.to_thread(
            hash_password,
            registration.password.get_secret_value(),
        ),
        is_verified=False,
        is_active=False,
    )
    db.add(user)

    try:
        await db.commit()
        await db.refresh(user)
    except IntegrityError as exc:
        await db.rollback()
        # Map database uniqueness conflicts to the same safe client response.
        raise DuplicateRegistrationError from exc
    except Exception:
        await db.rollback()
        raise

    return user
