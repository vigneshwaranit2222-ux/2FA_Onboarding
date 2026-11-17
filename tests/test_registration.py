from collections.abc import AsyncIterator

from argon2 import PasswordHasher
from httpx import ASGITransport, AsyncClient
import pytest

from app.database.session import get_db
from app.main import app


VALID_PAYLOAD = {
    "full_name": "  Ada   Lovelace ",
    "email": "Ada@example.com",
    "phone": "+1 (415) 555-2671",
    "password": "Correct-Horse7!Battery",
    "confirm_password": "Correct-Horse7!Battery",
}


class FakeSession:
    def __init__(self, duplicate: bool = False) -> None:
        self.duplicate = duplicate
        self.user = None

    async def scalar(self, _query):
        return 5 if self.duplicate else None

    def add(self, user) -> None:
        self.user = user

    async def commit(self) -> None:
        self.user.id = 11

    async def refresh(self, _user) -> None:
        return None

    async def rollback(self) -> None:
        return None


async def post_registration(payload: dict, session: FakeSession):
    async def override_get_db() -> AsyncIterator[FakeSession]:
        yield session

    app.dependency_overrides[get_db] = override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            return await client.post("/api/v1/auth/register", json=payload)
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_registration_creates_inactive_user_and_returns_no_password_hash() -> None:
    session = FakeSession()
    response = await post_registration(VALID_PAYLOAD, session)

    assert response.status_code == 201
    body = response.json()
    assert body["user"]["id"] == 11
    assert body["user"]["full_name"] == "Ada Lovelace"
    assert body["user"]["email"] == "ada@example.com"
    assert body["user"]["phone"] == "+14155552671"
    assert body["user"]["is_verified"] is False
    assert body["user"]["is_active"] is False
    assert "password" not in body["user"]
    assert "password_hash" not in body["user"]
    assert session.user.password_hash != VALID_PAYLOAD["password"]
    assert PasswordHasher().verify(session.user.password_hash, VALID_PAYLOAD["password"])


@pytest.mark.asyncio
async def test_duplicate_email_or_phone_returns_conflict() -> None:
    response = await post_registration(VALID_PAYLOAD, FakeSession(duplicate=True))

    assert response.status_code == 409
    assert response.json()["detail"] == "An account with this email or phone already exists"


@pytest.mark.asyncio
async def test_invalid_email_is_rejected() -> None:
    payload = {**VALID_PAYLOAD, "email": "not-an-email"}
    response = await post_registration(payload, FakeSession())

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_invalid_phone_is_rejected() -> None:
    payload = {**VALID_PAYLOAD, "phone": "555-0100"}
    response = await post_registration(payload, FakeSession())

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_weak_password_is_rejected() -> None:
    payload = {**VALID_PAYLOAD, "password": "weak", "confirm_password": "weak"}
    response = await post_registration(payload, FakeSession())

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_password_mismatch_is_rejected() -> None:
    payload = {**VALID_PAYLOAD, "confirm_password": "Different-Password8!"}
    response = await post_registration(payload, FakeSession())

    assert response.status_code == 422
