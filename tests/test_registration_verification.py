from datetime import datetime, timezone
import pytest
from argon2 import PasswordHasher
import httpx

from app.database.session import get_db
from app.main import app
from app.models.otp import OTPChallenge
from app.models.user import User
from app.services.otp_service import hash_otp


JWT_SECRET = "test-jwt-secret-long-enough-for-hmac-testing-phase"
OTP_SECRET = "test-otp-secret-long-enough-for-hmac-testing-phase"


class InMemoryDB:
    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.users_by_phone: dict[str, User] = {}
        self.challenges: list[OTPChallenge] = []
        self.commits = 0
        self.rollbacks = 0
        self.next_id = 1

    async def scalar(self, query):
        text = str(query)
        if "users.email" in text or "users.phone" in text or "FROM users" in text:
            for u in self.users.values():
                return u
            return None
        if "otp_challenges" in text:
            if self.challenges:
                return self.challenges[-1]
            return None
        return None

    def add(self, entity):
        if isinstance(entity, User):
            entity.id = self.next_id
            self.next_id += 1
            self.users[entity.email] = entity
            if entity.phone:
                self.users_by_phone[entity.phone] = entity
        elif isinstance(entity, OTPChallenge):
            entity.id = self.next_id
            self.next_id += 1
            self.challenges.append(entity)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1

    async def refresh(self, _instance):
        pass


@pytest.mark.asyncio
async def test_full_registration_and_multi_channel_verification_flow(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_SECRET)
    monkeypatch.setenv("OTP_HASH_SECRET", OTP_SECRET)
    monkeypatch.setattr("app.routers.auth.ensure_email_configured", lambda: None)
    monkeypatch.setattr("app.routers.auth.ensure_whatsapp_configured", lambda: None)

    dispatched_codes = {}

    async def fake_email_delivery(recipient: str, code: str) -> None:
        dispatched_codes["email"] = (recipient, code)

    async def fake_whatsapp_delivery(recipient: str, code: str) -> None:
        dispatched_codes["whatsapp"] = (recipient, code)

    monkeypatch.setattr("app.routers.auth.send_email_otp", fake_email_delivery)
    monkeypatch.setattr("app.routers.auth.send_whatsapp_otp", fake_whatsapp_delivery)

    user = User(
        id=77,
        full_name="Ada Lovelace",
        email="ada.onboarding@example.com",
        phone="+14155557788",
        password_hash=PasswordHasher().hash("Correct-Horse7!Battery"),
        email_verified=False,
        phone_verified=False,
        is_verified=False,
        is_active=False,
    )
    challenges = []

    class MockSession:
        def __init__(self):
            self.user = user
            self.challenges = challenges

        async def scalar(self, query):
            q_str = str(query)
            if "FROM users" in q_str:
                return self.user
            if "FROM otp_challenges" in q_str:
                params = getattr(query, "compile", lambda: None)().params if hasattr(query, "compile") else {}
                ch_type = params.get("channel_1") or params.get("channel")
                if not ch_type:
                    ch_type = "whatsapp" if "whatsapp" in str(params).lower() else "email"
                matching = [c for c in self.challenges if c.channel == ch_type]
                return matching[-1] if matching else None
            return None

        def add(self, item):
            if isinstance(item, OTPChallenge):
                item.id = len(self.challenges) + 1
                self.challenges.append(item)

        async def commit(self):
            pass

        async def rollback(self):
            pass

        async def refresh(self, _inst):
            pass

    async def override_db():
        yield MockSession()

    app.dependency_overrides[get_db] = override_db

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            # 1. User cannot login before verification
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": user.email, "password": "Correct-Horse7!Battery"},
            )
            assert login_resp.status_code == 401

            # 2. Request Email OTP
            email_send_resp = await client.post(
                "/api/v1/auth/email/send-otp",
                json={"email": user.email},
            )
            assert email_send_resp.status_code == 202
            body = email_send_resp.json()
            assert body["success"] is True
            assert body["channel"] == "email"

            # 3. Verify Email OTP
            _, email_code = dispatched_codes["email"]
            email_verify_resp = await client.post(
                "/api/v1/auth/email/verify-otp",
                json={"email": user.email, "code": email_code},
            )
            assert email_verify_resp.status_code == 200
            v_body = email_verify_resp.json()
            assert v_body["email_verified"] is True
            assert v_body["phone_verified"] is False
            assert v_body["is_verified"] is False

            # 4. User still cannot login (phone not verified yet)
            login_resp2 = await client.post(
                "/api/v1/auth/login",
                json={"email": user.email, "password": "Correct-Horse7!Battery"},
            )
            assert login_resp2.status_code == 401

            # 5. Request WhatsApp OTP
            wa_send_resp = await client.post(
                "/api/v1/auth/whatsapp/send-otp",
                json={"phone": user.phone},
            )
            assert wa_send_resp.status_code == 202
            wa_body = wa_send_resp.json()
            assert wa_body["success"] is True
            assert wa_body["channel"] == "whatsapp"

            # 6. Verify WhatsApp OTP
            _, wa_code = dispatched_codes["whatsapp"]
            wa_verify_resp = await client.post(
                "/api/v1/auth/whatsapp/verify-otp",
                json={"phone": user.phone, "code": wa_code},
            )
            assert wa_verify_resp.status_code == 200
            wa_v_body = wa_verify_resp.json()
            assert wa_v_body["phone_verified"] is True
            assert wa_v_body["email_verified"] is True
            assert wa_v_body["is_verified"] is True

            # Account is now fully verified and activated!
            assert user.is_verified is True
            assert user.is_active is True
    finally:
        app.dependency_overrides.pop(get_db, None)
