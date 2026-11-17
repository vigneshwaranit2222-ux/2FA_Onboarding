"""Full local flow, enabled only against the explicitly named test database."""

import os
from collections.abc import AsyncIterator
from io import BytesIO
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import httpx
import pyotp
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from docx import Document

from app.database.session import get_db
from app.main import app
from app.routers import auth as auth_router
from app.routers import resume as resume_router


@pytest_asyncio.fixture
async def postgres_client(
    monkeypatch,
) -> AsyncIterator[tuple[httpx.AsyncClient, dict[str, str], Path]]:
    database_url = os.getenv("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("Set TEST_DATABASE_URL to the migrated resume_onboarding_test database")
    if make_url(database_url).database != "resume_onboarding_test":
        pytest.fail("Integration tests refuse to connect unless the database is resume_onboarding_test")

    monkeypatch.setenv("JWT_SECRET_KEY", "phase6-test-jwt-secret-at-least-32-chars")
    monkeypatch.setenv("OTP_HASH_SECRET", "phase6-test-otp-secret-at-least-32-chars")
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.setattr(auth_router, "ensure_email_configured", lambda: None)
    monkeypatch.setattr(auth_router, "ensure_whatsapp_configured", lambda: None)

    issued_codes = {}

    async def fake_email_sender(recipient: str, code: str) -> None:
        issued_codes["email"] = code

    async def fake_whatsapp_sender(recipient: str, code: str) -> None:
        issued_codes["whatsapp"] = code

    monkeypatch.setattr(auth_router, "send_email_otp", fake_email_sender)
    monkeypatch.setattr(auth_router, "send_whatsapp_otp", fake_whatsapp_sender)
    upload_dir = Path("uploads") / f"phase6-test-{uuid4().hex}"
    upload_dir.mkdir(parents=True, exist_ok=False)
    monkeypatch.setattr(resume_router, "UPLOAD_DIR", upload_dir)

    engine = create_async_engine(database_url, echo=False)
    async with engine.connect() as connection:
        outer_transaction = await connection.begin()
        session_factory = async_sessionmaker(
            bind=connection,
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )

        async def override_get_db() -> AsyncIterator[AsyncSession]:
            async with session_factory() as session:
                yield session

        app.dependency_overrides[get_db] = override_get_db
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                yield client, issued_codes, upload_dir
        finally:
            app.dependency_overrides.pop(get_db, None)
            await outer_transaction.rollback()
            for file_path in upload_dir.iterdir():
                if file_path.is_file():
                    file_path.unlink()
            upload_dir.rmdir()
    await engine.dispose()


@pytest.mark.asyncio
async def test_registration_verification_totp_sessions_and_owned_resume(postgres_client) -> None:
    client, issued_codes, upload_dir = postgres_client
    unique_id = uuid4()
    email = f"phase6-{unique_id.hex}@example.com"
    phone_digits = f"{unique_id.int % 10_000_000_000:010d}"
    phone = "+1" + phone_digits

    registration = await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Phase Six User",
            "email": email,
            "phone": phone,
            "password": "Correct-Horse7!Battery",
            "confirm_password": "Correct-Horse7!Battery",
        },
    )
    assert registration.status_code == 201

    assert (await client.post("/api/v1/auth/email/send-otp", json={"email": email})).status_code == 202
    email_code = issued_codes["email"]
    assert (
        await client.post(
            "/api/v1/auth/email/verify-otp",
            json={"email": email, "code": email_code},
        )
    ).status_code == 200

    assert (
        await client.post("/api/v1/auth/whatsapp/send-otp", json={"phone": phone})
    ).status_code == 202
    whatsapp_code = issued_codes["whatsapp"]
    assert (
        await client.post(
            "/api/v1/auth/whatsapp/verify-otp",
            json={"phone": phone, "code": whatsapp_code},
        )
    ).status_code == 200

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "Correct-Horse7!Battery"},
    )
    assert login.status_code == 200
    first_session = login.json()
    first_auth = {"Authorization": f"Bearer {first_session['access_token']}"}

    setup = await client.post("/api/v1/auth/totp/setup", headers=first_auth)
    assert setup.status_code == 200
    provisioning_uri = setup.json()["provisioning_uri"]
    totp_secret = parse_qs(urlparse(provisioning_uri).query)["secret"][0]
    enrollment = await client.post(
        "/api/v1/auth/totp/verify",
        headers=first_auth,
        json={"code": pyotp.TOTP(totp_secret).now()},
    )
    assert enrollment.status_code == 200
    recovery_codes = enrollment.json()["recovery_codes"]

    mfa_login = await client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": "Correct-Horse7!Battery",
            "recovery_code": recovery_codes[0],
        },
    )
    assert mfa_login.status_code == 200
    session = mfa_login.json()
    auth = {"Authorization": f"Bearer {session['access_token']}"}

    disabled = await client.post(
        "/api/v1/auth/totp/disable",
        headers=auth,
        json={
            "current_password": "Correct-Horse7!Battery",
            "recovery_code": recovery_codes[1],
        },
    )
    assert disabled.status_code == 200

    resume_doc = Document()
    resume_doc.add_paragraph("Phase Six User")
    resume_doc.add_paragraph(email)
    resume_doc.add_paragraph("Python FastAPI")
    resume_bytes = BytesIO()
    resume_doc.save(resume_bytes)
    upload = await client.post(
        "/api/v1/resume/parse",
        headers=auth,
        files={"file": ("phase-six.docx", resume_bytes.getvalue(), "application/docx")},
    )
    assert upload.status_code == 200
    resume_id = upload.json()["resume_id"]
    rows = await client.get("/api/v1/users/me/resumes", headers=auth)
    assert rows.status_code == 200
    assert any(row["id"] == resume_id for row in rows.json())
    detail = await client.get(f"/api/v1/users/me/resumes/{resume_id}", headers=auth)
    assert detail.status_code == 200
    assert detail.json()["extracted_data"]["full_name"] == "Phase Six User"
    assert len(list(upload_dir.glob("*.docx"))) == 1

    refreshed = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": session["refresh_token"]},
    )
    assert refreshed.status_code == 200
    rotated = refreshed.json()
    logout = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {rotated['access_token']}"},
        json={"refresh_token": rotated["refresh_token"]},
    )
    assert logout.status_code == 200
    assert (
        await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {rotated['access_token']}"},
        )
    ).status_code == 401
