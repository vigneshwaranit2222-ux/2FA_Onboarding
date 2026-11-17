from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import pytest
from docx import Document

from app.database.session import get_db
from app.main import app
from app.models.user import User


JWT_SECRET = "test-jwt-secret-long-enough-for-hmac-testing"
SESSION_ID = "11111111-1111-4111-8111-111111111111"


class FakeSession:
    def __init__(self, user) -> None:
        self.results = [user, 1]
        self.added = []

    async def scalar(self, _query):
        return self.results.pop(0)

    def add(self, row) -> None:
        self.added.append(row)

    async def commit(self) -> None:
        for row in self.added:
            if row.id is None:
                row.id = 101

    async def rollback(self) -> None:
        return None

    async def refresh(self, row) -> None:
        if row.id is None:
            row.id = 101


def make_user() -> User:
    return User(
        id=73,
        full_name="Ada Lovelace",
        email="ada@example.com",
        phone="+14155552671",
        password_hash="not-used",
        email_verified=True,
        phone_verified=True,
        is_verified=True,
        is_active=True,
    )


def make_token() -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": "73",
            "sid": SESSION_ID,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "type": "access",
        },
        JWT_SECRET,
        algorithm="HS256",
    )


@pytest.mark.asyncio
async def test_resume_upload_requires_auth_and_persists_owner(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    doc = Document()
    doc.add_paragraph("Ada Lovelace")
    doc.add_paragraph("ada@example.com")
    doc.add_paragraph("Python FastAPI")
    content = BytesIO()
    doc.save(content)
    db = FakeSession(make_user())

    async def override_get_db() -> AsyncIterator[FakeSession]:
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/resume/parse",
                files={
                    "file": (
                        "ada.docx",
                        content.getvalue(),
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    )
                },
                headers={"Authorization": f"Bearer {make_token()}"},
            )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    assert db.added[0].user_id == 73
    assert db.added[0].extracted_data["full_name"] == "Ada Lovelace"
    Path(db.added[0].file_path).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_resume_upload_rejects_missing_access_token(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/v1/resume/parse",
            files={"file": ("empty.pdf", b"not-a-pdf", "application/pdf")},
        )
    assert response.status_code == 401
