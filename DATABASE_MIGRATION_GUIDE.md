# Database migration and adoption guide

## Pre-migration database audit

The configured database is `resume_onboarding`. Inspection found the original Day 1 schema only: `users`, `user_resumes`, and `otp_challenges`; no `alembic_version` table or migration history exists.

- `users`: `id`, `full_name`, `email`, `phone`, `password_hash`, `is_verified`, `is_active`, `created_at`; unique email index and ID index.
- `user_resumes`: `id`, nullable `user_id`, file metadata, extracted text, JSONB data, `created_at`; FK to `users` and ID index.
- `otp_challenges`: `id`, `user_id`, `channel`, `otp_hash`, `expires_at`, `is_verified`, `attempts`, `created_at`; FK to `users` and ID index.
- Row counts: 0 users, 1 resume, 0 OTP challenges. The existing resume has `user_id IS NULL`; preserve it as an unowned historical record.
- No users currently have phone values, so there are no existing phone duplicates. No OTP rows require legacy-purpose mapping.

These were the verified pre-migration observations. The application database remains the same database; its original resume row was preserved.

## Prepared revisions

### `0001_day1`

Creates the three original Day 1 tables for a fresh database, matching the audited schema and indexes. This is an adoption baseline, not an incremental migration for the current database.

### `0002_auth`

Adds email/phone verification, TOTP, login lockout, and recovery-code fields to `users`; adds OTP purpose, resend, sent, and verified metadata; adds the phone uniqueness constraint and OTP lookup index; creates `refresh_tokens` with hashed-token storage indexes and foreign keys.

The OTP migration backfills `purpose` from `channel`, `last_sent_at` from `created_at`, and `verified_at` from `created_at` for old verified records. Unknown historical channels are labeled `legacy`, not deleted. It fills null attempts with zero. Current counts show these backfills affect no rows.

Neither upgrade drops, truncates, renames, or recreates an existing application table. The incremental downgrade removes new columns and the refresh-token table, so it would discard authentication/session data; do not run a downgrade without a separate backup and explicit review.

## Adoption procedure for the existing database

## Migration execution record

Approved and applied on 2026-11-13:

1. Created a custom-format backup at `backups/resume_onboarding_pre_phase6_20261113.dump`; `pg_restore --list` confirmed it is readable.
2. Rechecked the application database immediately before migration: exact baseline tables and columns, 0 users, 1 unowned resume, 0 OTP rows, no duplicate non-null phones, and no other active database sessions.
3. Stamped the existing schema at `0001_day1` without running baseline table creation, then upgraded to `0002_auth`.
4. Verified Alembic reports `0002_auth`, auth columns/indexes and `refresh_tokens` exist, and counts remain 0 users, 1 resume, 0 OTP challenges, 0 refresh tokens. The resume remains unowned.
5. Created `resume_onboarding_test`, applied both revisions, and passed the PostgreSQL-backed end-to-end test there.

Do **not** stamp the existing database at `head`; that would skip the authentication changes. Do not use `Base.metadata.create_all()` for application schema setup.

## Fresh and test databases

For a genuinely empty database, `python -m alembic upgrade head` runs `0001_day1` then `0002_auth`. The dedicated `resume_onboarding_test` database now has both revisions applied and is used for PostgreSQL integration tests. Never drop or truncate it as a test shortcut.

## Configuration notes

`migrations/env.py` imports all model modules, uses `Base.metadata`, loads `.env` relative to the project root, and applies the same repeated `DATABASE_URL=` prefix normalization as the application session. It escapes percent characters for Alembic configuration parsing. It does not auto-run migrations at application startup.
