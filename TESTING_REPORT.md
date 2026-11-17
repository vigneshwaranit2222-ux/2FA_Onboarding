# Testing report

Latest local automated run (against the project virtual environment):

- `venv\Scripts\python.exe -m pytest -q` with `TEST_DATABASE_URL=resume_onboarding_test`: **62 passed**.
- `pip check`: **No broken requirements found**.
- `compileall app tests migrations`: passed.
- `alembic history`: shows `0001_day1 -> 0002_auth (head)`.
- PostgreSQL end-to-end flow: passed against `resume_onboarding_test` after applying both revisions.
- OpenAPI inspection: 16 `/api/v1` route paths, including registration, login, OTP, TOTP, refresh/logout, profile, and user-owned resume routes.

Coverage includes registration validation/hashing, OTP lifecycle and provider failure handling, TOTP encryption/QR/replay/lockout/recovery, JWT validation, login/MFA, refresh rotation/reuse, logout, profile ownership, resume ownership/download, and DOCX parser regression.

Limitations: most unit tests use fake async database sessions; one end-to-end flow uses PostgreSQL. Email and WhatsApp delivery are mocked, and no real provider delivery was attempted.
