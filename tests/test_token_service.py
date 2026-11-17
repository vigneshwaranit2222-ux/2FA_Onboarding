import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.services.token_service import (
    InvalidRefreshTokenError,
    revoke_refresh_token,
    rotate_refresh_token,
)


class FakeSession:
    def __init__(self, *results, rows=None) -> None:
        self.results = list(results)
        self.rows = list(rows or [])
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    async def scalar(self, _query):
        if self.results:
            return self.results.pop(0)
        return self.added[-1] if self.added else None

    def add(self, row) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        for row in self.added:
            if row.id is None:
                row.id = max([item.id or 0 for item in self.rows] + [0]) + 1
                self.rows.append(row)

    async def execute(self, _query):
        now = datetime.now(timezone.utc)
        family_id = self.rows[0].family_id if self.rows else None
        for row in self.rows:
            if row.family_id == family_id and row.revoked_at is None:
                row.revoked_at = now

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


def make_user() -> User:
    return User(
        id=9,
        is_active=True,
        is_verified=True,
        email_verified=True,
        phone_verified=True,
    )


def make_refresh_token(raw: str, *, revoked_at=None, expires_in_days=2) -> RefreshToken:
    now = datetime.now(timezone.utc)
    return RefreshToken(
        id=1,
        user_id=9,
        family_id="11111111-1111-4111-8111-111111111111",
        token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        expires_at=now + timedelta(days=expires_in_days),
        created_at=now,
        revoked_at=revoked_at,
    )


@pytest.mark.asyncio
async def test_refresh_rotates_token_and_links_replacement(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-long-enough-for-hmac-testing")
    old = make_refresh_token("old-refresh-token")
    db = FakeSession(old, make_user(), rows=[old])

    pair = await rotate_refresh_token(db, "old-refresh-token")

    assert old.revoked_at is not None
    assert old.replaced_by_token_id == 2
    assert len(db.rows) == 2
    assert db.rows[1].revoked_at is None
    assert pair.family_id == old.family_id
    assert pair.refresh_token != "old-refresh-token"
    assert db.commits == 1


@pytest.mark.asyncio
async def test_reused_refresh_token_revokes_the_active_family() -> None:
    now = datetime.now(timezone.utc)
    old = make_refresh_token("old-refresh-token", revoked_at=now)
    active = RefreshToken(
        id=2,
        user_id=9,
        family_id=old.family_id,
        token_hash=hashlib.sha256(b"new-refresh-token").hexdigest(),
        expires_at=now + timedelta(days=2),
        created_at=now,
        revoked_at=None,
    )
    db = FakeSession(old, rows=[old, active])

    with pytest.raises(InvalidRefreshTokenError):
        await rotate_refresh_token(db, "old-refresh-token")
    assert active.revoked_at is not None
    assert db.commits == 1


@pytest.mark.asyncio
async def test_expired_refresh_token_is_revoked_and_rejected() -> None:
    expired = make_refresh_token("expired-token", expires_in_days=-1)
    db = FakeSession(expired, rows=[expired])

    with pytest.raises(InvalidRefreshTokenError):
        await rotate_refresh_token(db, "expired-token")
    assert expired.revoked_at is not None
    assert db.commits == 1


@pytest.mark.asyncio
async def test_logout_revokes_all_tokens_in_the_session_family() -> None:
    first = make_refresh_token("current-token")
    second = RefreshToken(
        id=2,
        user_id=9,
        family_id=first.family_id,
        token_hash=hashlib.sha256(b"older-token").hexdigest(),
        expires_at=first.expires_at,
        created_at=first.created_at,
        revoked_at=None,
    )
    db = FakeSession(first, rows=[first, second])

    assert await revoke_refresh_token(db, 9, "current-token") is True
    assert first.revoked_at is not None and second.revoked_at is not None
    assert db.commits == 1


@pytest.mark.asyncio
async def test_logout_with_stale_rotated_token_revokes_current_family() -> None:
    now = datetime.now(timezone.utc)
    stale = make_refresh_token("stale-token", revoked_at=now)
    active = RefreshToken(
        id=2,
        user_id=9,
        family_id=stale.family_id,
        token_hash=hashlib.sha256(b"current-token").hexdigest(),
        expires_at=now + timedelta(days=2),
        created_at=now,
        revoked_at=None,
    )
    db = FakeSession(stale, rows=[stale, active])

    assert await revoke_refresh_token(db, 9, "stale-token") is True
    assert active.revoked_at is not None
    assert db.commits == 1
