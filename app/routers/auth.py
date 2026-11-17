import asyncio
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    LogoutResponse,
    RefreshRequest,
    RegistrationRequest,
    RegistrationResponse,
    TokenResponse,
)
from app.schemas.otp import (
    EmailOTPVerifyRequest,
    EmailOTPSendRequest,
    OTPActionResponse,
    OTPVerificationResponse,
    WhatsAppOTPVerifyRequest,
    WhatsAppOTPSendRequest,
)
from app.schemas.totp import (
    TOTPCodeRequest,
    TOTPDisableRequest,
    TOTPDisableResponse,
    TOTPEnrollmentResponse,
    TOTPSetupResponse,
)
from app.schemas.user import UserProfile, UserProfileUpdate
from app.core.security import get_current_user
from app.services.email_service import ensure_email_configured, send_email_otp
from app.services.otp_service import (
    InvalidOTPError,
    OTPConfigurationError,
    OTPDeliveryError,
    ensure_otp_configured,
    get_otp_ttl_seconds,
    issue_otp,
    verify_otp,
)
from app.services.registration_service import (
    DuplicateRegistrationError,
    register_user,
)
from app.services.auth_service import InvalidCredentialsError, authenticate_user
from app.services.password_service import verify_password
from app.services.totp_service import (
    InvalidRecoveryCodeError,
    InvalidTOTPCodeError,
    TOTPAlreadyEnabledError,
    TOTPAttemptLockedError,
    TOTPConfigurationError,
    TOTPNotEnabledError,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    disable_totp,
)
from app.services.whatsapp_service import (
    ensure_whatsapp_configured,
    send_whatsapp_otp,
)
from app.services.token_service import (
    InvalidRefreshTokenError,
    TokenConfigurationError,
    revoke_refresh_token,
    rotate_refresh_token,
)
from app.models.user import User
from app.models.refresh_token import RefreshToken


router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=RegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new account",
    description=(
        "Create an inactive account. Email and phone verification are handled "
        "by the verification endpoints. The password is stored as an Argon2id hash."
    ),
    responses={
        status.HTTP_201_CREATED: {"description": "Account created"},
        status.HTTP_409_CONFLICT: {"description": "Email or phone is already registered"},
        422: {"description": "Request validation failed"},
    },
)
async def register(
    registration: RegistrationRequest,
    db: AsyncSession = Depends(get_db),
) -> RegistrationResponse:
    try:
        user = await register_user(db, registration)
    except DuplicateRegistrationError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email or phone already exists",
        ) from None

    return RegistrationResponse(
        user=user,
        message="Registration successful. Verify your email and phone to activate your account.",
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and create a session",
    description="Requires verified email and phone. If TOTP is enabled, provide a TOTP or one-time recovery code.",
    responses={
        200: {"description": "Authenticated; access and refresh tokens issued"},
        401: {"description": "Credentials, account state, or second factor is invalid"},
        503: {"description": "Token or MFA configuration is unavailable"},
    },
)
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    try:
        pair = await authenticate_user(db, request)
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email, password, account state, or second factor",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except TOTPConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authenticator verification is not configured",
        ) from None
    except TokenConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured",
        ) from None
    return TokenResponse(**pair.response())


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate a refresh token",
    responses={
        200: {"description": "Token rotated"},
        401: {"description": "Refresh token is invalid, expired, or revoked"},
        503: {"description": "Token configuration is unavailable"},
    },
)
async def refresh(
    request: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    try:
        pair = await rotate_refresh_token(db, request.refresh_token.get_secret_value())
    except InvalidRefreshTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        ) from None
    except TokenConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured",
        ) from None
    return TokenResponse(**pair.response())


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Revoke the current refresh-token session",
    description="Requires a valid access token and the corresponding refresh token.",
    responses={
        200: {"description": "Session revoked"},
        401: {"description": "Authentication required"},
    },
)
async def logout(
    request: LogoutRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LogoutResponse:
    await revoke_refresh_token(
        db,
        current_user.id,
        request.refresh_token.get_secret_value(),
    )
    return LogoutResponse(message="Session revoked")


@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get the authenticated profile",
    responses={401: {"description": "Authentication required"}},
)
async def get_me(current_user: User = Depends(get_current_user)) -> UserProfile:
    return UserProfile.model_validate(current_user)


@router.patch(
    "/me",
    response_model=UserProfile,
    summary="Update the authenticated profile",
    description="Email cannot be changed here. Changing phone number disables the account until phone verification succeeds again.",
    responses={
        200: {"description": "Profile updated"},
        401: {"description": "Authentication required"},
        409: {"description": "Phone number is already registered"},
    },
)
async def update_me(
    update_request: UserProfileUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserProfile:
    try:
        if update_request.full_name is not None:
            current_user.full_name = update_request.full_name

        phone_changed = (
            update_request.phone is not None
            and update_request.phone != current_user.phone
        )
        if phone_changed:
            duplicate = await db.scalar(
                select(User.id).where(
                    User.phone == update_request.phone,
                    User.id != current_user.id,
                )
            )
            if duplicate is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An account with this phone number already exists",
                )
            current_user.phone = update_request.phone
            current_user.phone_verified = False
            current_user.is_verified = False
            current_user.is_active = False
            await db.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.user_id == current_user.id,
                    RefreshToken.revoked_at.is_(None),
                )
                .values(revoked_at=datetime.now(timezone.utc))
            )
        await db.commit()
        await db.refresh(current_user)
    except HTTPException:
        await db.rollback()
        raise
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this phone number already exists",
        ) from None
    except Exception:
        await db.rollback()
        raise
    return UserProfile.model_validate(current_user)


def _raise_provider_error(exc: Exception, channel: str) -> None:
    if isinstance(exc, OTPConfigurationError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{channel} verification is not configured",
        ) from None
    if isinstance(exc, OTPDeliveryError):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"{channel} provider did not accept the verification message",
        ) from None


@router.post(
    "/email/send-otp",
    response_model=OTPActionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request an email verification code",
    responses={
        202: {"description": "Request accepted when the account is eligible"},
        502: {"description": "Email provider rejected the message"},
        503: {"description": "Email verification is not configured"},
    },
)
async def send_email_verification_code(
    request: EmailOTPSendRequest,
    db: AsyncSession = Depends(get_db),
) -> OTPActionResponse:
    try:
        ensure_email_configured()
        ensure_otp_configured()
        await issue_otp(db, "email", str(request.email), send_email_otp)
    except (OTPConfigurationError, OTPDeliveryError) as exc:
        _raise_provider_error(exc, "Email")
    ttl_seconds = get_otp_ttl_seconds() if os.getenv("OTP_HASH_SECRET") else 300
    return OTPActionResponse(
        success=True,
        message="If the account is eligible, the verification message was accepted for processing.",
        channel="email",
        expires_in_seconds=ttl_seconds,
    )


@router.post(
    "/email/verify-otp",
    response_model=OTPVerificationResponse,
    summary="Verify an email code",
    responses={
        200: {"description": "Email verified"},
        400: {"description": "Code is invalid, expired, or already used"},
        503: {"description": "Email verification is not configured"},
    },
)
async def verify_email_code(
    request: EmailOTPVerifyRequest,
    db: AsyncSession = Depends(get_db),
) -> OTPVerificationResponse:
    try:
        await verify_otp(db, "email", str(request.email), request.code)
    except InvalidOTPError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code is invalid or expired",
        ) from None
    except OTPConfigurationError as exc:
        _raise_provider_error(exc, "Email")

    user = await db.scalar(select(User).where(User.email == str(request.email).lower()))
    return OTPVerificationResponse(
        success=True,
        verified=True,
        message="Email verified successfully",
        email_verified=user.email_verified if user else True,
        phone_verified=user.phone_verified if user else False,
        is_verified=user.is_verified if user else False,
    )


@router.post(
    "/whatsapp/send-otp",
    response_model=OTPActionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a WhatsApp phone verification code",
    responses={
        202: {"description": "Request accepted when the account is eligible"},
        502: {"description": "WhatsApp provider rejected the message"},
        503: {"description": "WhatsApp verification is not configured"},
    },
)
async def send_whatsapp_verification_code(
    request: WhatsAppOTPSendRequest,
    db: AsyncSession = Depends(get_db),
) -> OTPActionResponse:
    try:
        ensure_whatsapp_configured()
        ensure_otp_configured()
        await issue_otp(db, "whatsapp", request.phone, send_whatsapp_otp)
    except (OTPConfigurationError, OTPDeliveryError) as exc:
        _raise_provider_error(exc, "WhatsApp")
    ttl_seconds = get_otp_ttl_seconds() if os.getenv("OTP_HASH_SECRET") else 300
    return OTPActionResponse(
        success=True,
        message="If the account is eligible, the verification message was accepted for processing.",
        channel="whatsapp",
        expires_in_seconds=ttl_seconds,
    )


@router.post(
    "/whatsapp/verify-otp",
    response_model=OTPVerificationResponse,
    summary="Verify a WhatsApp phone code",
    responses={
        200: {"description": "Phone verified"},
        400: {"description": "Code is invalid, expired, or already used"},
        503: {"description": "WhatsApp verification is not configured"},
    },
)
async def verify_whatsapp_code(
    request: WhatsAppOTPVerifyRequest,
    db: AsyncSession = Depends(get_db),
) -> OTPVerificationResponse:
    try:
        await verify_otp(db, "whatsapp", request.phone, request.code)
    except InvalidOTPError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code is invalid or expired",
        ) from None
    except OTPConfigurationError as exc:
        _raise_provider_error(exc, "WhatsApp")

    user = await db.scalar(select(User).where(User.phone == request.phone))
    return OTPVerificationResponse(
        success=True,
        verified=True,
        message="Phone verified successfully",
        email_verified=user.email_verified if user else False,
        phone_verified=user.phone_verified if user else True,
        is_verified=user.is_verified if user else False,
    )


@router.post(
    "/totp/setup",
    response_model=TOTPSetupResponse,
    summary="Begin authenticator app enrollment",
    description="Requires a valid access token. The provisioning URI and QR code reveal the pending secret once.",
    responses={
        200: {"description": "TOTP enrollment started"},
        401: {"description": "Authentication required"},
        409: {"description": "TOTP is already enabled"},
        503: {"description": "TOTP encryption is not configured"},
    },
)
async def setup_totp(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TOTPSetupResponse:
    try:
        provisioning_uri, qr_data_uri = begin_totp_enrollment(current_user)
        await db.commit()
    except TOTPAlreadyEnabledError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Authenticator is already enabled",
        ) from None
    except TOTPConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TOTP enrollment is not configured",
        ) from None
    except Exception:
        await db.rollback()
        raise
    return TOTPSetupResponse(
        provisioning_uri=provisioning_uri,
        qr_code_data_uri=qr_data_uri,
        message="Scan the QR code, then verify a code to enable the authenticator.",
    )


@router.post(
    "/totp/verify",
    response_model=TOTPEnrollmentResponse,
    summary="Confirm authenticator enrollment",
    description="Requires a valid access token. Recovery codes are returned once after successful enrollment.",
    responses={
        200: {"description": "TOTP enabled; save the one-time recovery codes"},
        400: {"description": "Code is invalid or outside the allowed time window"},
        401: {"description": "Authentication required"},
        429: {"description": "TOTP verification temporarily locked"},
    },
)
async def verify_totp_enrollment(
    request: TOTPCodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TOTPEnrollmentResponse:
    try:
        recovery_codes = confirm_totp_enrollment(current_user, request.code)
        await db.commit()
    except InvalidTOTPCodeError:
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authenticator code is invalid or expired",
        ) from None
    except TOTPAttemptLockedError:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Authenticator verification is temporarily locked",
        ) from None
    except TOTPNotEnabledError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Start authenticator enrollment first",
        ) from None
    except TOTPAlreadyEnabledError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Authenticator is already enabled",
        ) from None
    except TOTPConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TOTP enrollment is not configured",
        ) from None
    except Exception:
        await db.rollback()
        raise
    return TOTPEnrollmentResponse(
        totp_enabled=True,
        recovery_codes=recovery_codes,
        message="Authenticator enabled. Store these recovery codes securely; they will not be shown again.",
    )


@router.post(
    "/totp/disable",
    response_model=TOTPDisableResponse,
    summary="Disable authenticator app protection",
    description="Requires a valid access token, current password, and one unused TOTP or recovery code.",
    responses={
        200: {"description": "TOTP disabled"},
        400: {"description": "Password or authenticator code is invalid"},
        401: {"description": "Authentication required"},
        409: {"description": "TOTP is not enabled"},
        429: {"description": "TOTP verification temporarily locked"},
    },
)
async def disable_totp_enrollment(
    request: TOTPDisableRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TOTPDisableResponse:
    password_matches = await asyncio.to_thread(
        verify_password,
        request.current_password.get_secret_value(),
        current_user.password_hash,
    )
    if not password_matches:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password or authenticator code is invalid",
        )
    try:
        disable_totp(
            current_user,
            code=request.code,
            recovery_code=request.recovery_code,
        )
        await db.commit()
    except (InvalidTOTPCodeError, InvalidRecoveryCodeError):
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password or authenticator code is invalid",
        ) from None
    except TOTPAttemptLockedError:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Authenticator verification is temporarily locked",
        ) from None
    except TOTPNotEnabledError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Authenticator is not enabled",
        ) from None
    except TOTPConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TOTP enrollment is not configured",
        ) from None
    except Exception:
        await db.rollback()
        raise
    return TOTPDisableResponse(
        totp_enabled=False,
        message="Authenticator disabled successfully",
    )
