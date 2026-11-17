from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import pytest

from app.database.session import get_db
from app.main import app
from app.models.resume import UserResume
from app.models.user import User
from app.routers import users as users_router


JWT_SECRET = "test-jwt-secret-long-enough-for-hmac-testing"
SESSION_ID = "11111111-1111-4111-8111-111111111111"


class Result:
    def __init__(self, rows) -> None:
        self.rows = rows

    def all(self):
        return self.rows


class FakeSession:
    def __init__(self, *results, rows=None) -> None:
        self.results = list(results)
        self.rows = rows or []
        self.commits = 0

    async def scalar(self, _query):
        return self.results.pop(0) if self.results else None

    async def scalars(self, _query):
        return Result(self.rows)

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, _instance) -> None:
        return None

    async def rollback(self) -> None:
        return None


def make_user() -> User:
    return User(
        id=55,
        full_name="Ada Lovelace",
        email="ada@example.com",
        phone="+14155552671",
        password_hash="not-returned",
        email_verified=True,
        phone_verified=True,
        is_verified=True,
        is_active=True,
    )


def make_token() -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": "55",
            "sid": SESSION_ID,
            "iat": now,
            "exp": now.replace(microsecond=0).timestamp() + 300,
            "type": "access",
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def make_resume(path: str | None = None) -> UserResume:
    return UserResume(
        id=8,
        user_id=55,
        file_name="Ada Resume.pdf",
        file_path=path,
        extracted_text="Ada Lovelace Python",
        extracted_data={"full_name": "Ada Lovelace", "skills": ["Python"]},
        created_at=datetime.now(timezone.utc),
    )


async def request_as_user(method, path, db, *, token=None, payload=None):
    async def override_get_db() -> AsyncIterator[FakeSession]:
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            return await client.request(
                method,
                path,
                json=payload,
                headers={"Authorization": f"Bearer {token}"} if token else {},
            )
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_resume_list_and_detail_are_scoped_to_current_user(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    user = make_user()
    resume = make_resume()

    listed = await request_as_user(
        "GET",
        "/api/v1/users/me/resumes",
        FakeSession(user, 1, rows=[resume]),
        token=make_token(),
    )
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == resume.id
    assert "file_path" not in listed.json()[0]

    detail = await request_as_user(
        "GET",
        f"/api/v1/users/me/resumes/{resume.id}",
        FakeSession(user, 1, resume),
        token=make_token(),
    )
    assert detail.status_code == 200
    assert detail.json()["extracted_text"] == "Ada Lovelace Python"


@pytest.mark.asyncio
async def test_other_or_missing_user_resume_returns_not_found(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    response = await request_as_user(
        "GET",
        "/api/v1/users/me/resumes/999",
        FakeSession(make_user(), 1, None),
        token=make_token(),
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Resume not found"


@pytest.mark.asyncio
async def test_extracted_resume_data_can_be_corrected_only_for_owned_record(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    resume = make_resume()
    db = FakeSession(make_user(), 1, resume)
    response = await request_as_user(
        "PATCH",
        f"/api/v1/users/me/resumes/{resume.id}",
        db,
        token=make_token(),
        payload={"full_name": "  Ada  Byron  Lovelace ", "skills": ["Python", "FastAPI"]},
    )

    assert response.status_code == 200
    assert response.json()["extracted_data"]["full_name"] == "Ada Byron Lovelace"
    assert response.json()["extracted_data"]["skills"] == ["Python", "FastAPI"]
    assert db.commits == 1


@pytest.mark.asyncio
async def test_owned_resume_file_download_stays_under_upload_root(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    file_path = Path("uploads") / f"phase5-{uuid4().hex}.pdf"
    file_path.write_bytes(b"%PDF-test")
    monkeypatch.setattr(users_router, "UPLOAD_ROOT", file_path.parent.resolve())
    resume = make_resume(str(file_path))

    try:
        response = await request_as_user(
            "GET",
            f"/api/v1/users/me/resumes/{resume.id}/file",
            FakeSession(make_user(), 1, resume),
            token=make_token(),
        )
    finally:
        file_path.unlink(missing_ok=True)
    assert response.status_code == 200
    assert response.content == b"%PDF-test"
    assert "filename*=utf-8''Ada%20Resume.pdf" in response.headers["content-disposition"]
