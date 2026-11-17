# Security audit report

This is a code review summary, not a formal compliance assessment.

## Implemented controls

- Argon2id password hashing; plaintext passwords are not stored or returned.
- Email normalization, E.164 phone validation, duplicate checks, and inactive accounts until both contact channels verify.
- Six-digit OTP generation, HMAC-SHA256 storage bound to user and purpose, expiry, attempt limits, resend cooldown/count, and single-use verification.
- SMTP delivery over STARTTLS or implicit TLS; Meta WhatsApp Cloud API provider requests an authentication template. Provider credentials are environment-only.
- TOTP secrets are Fernet-encrypted at rest. Enrollment requires a code; valid time steps cannot be reused. Recovery codes are random, one-time, and stored as hashes.
- Login checks account verification and requires TOTP/recovery code when enabled. Failed passwords and TOTP attempts have temporary lockouts.
- JWT algorithm allowlist and required `sub`, `sid`, `iat`, `exp`, and `type` claims. Access tokens are bound to an active refresh-token family.
- Refresh values are high-entropy opaque tokens stored as SHA-256 hashes; rotation reuse revokes the family. Logout revokes the family and makes its access tokens fail subsequent checks.
- Profile and resume queries are ownership-scoped. Resume file downloads are constrained to the configured uploads root. SQL echo is disabled.

## Remaining risks and limitations

- Authentication migrations `0001_day1` and `0002_auth` are applied to `resume_onboarding`; the separate `resume_onboarding_test` database is also migrated. The application database is backed up at `backups/resume_onboarding_pre_phase6_20261113.dump`.
- `.env` currently lacks JWT, OTP HMAC, TOTP encryption, SMTP, and WhatsApp settings. Real provider delivery and live login are therefore not verified.
- No IP/network rate limiter is implemented. Account-level attempt limits and OTP resend controls do not stop distributed requests.
- WhatsApp API acceptance is not a delivery receipt; status webhooks are not implemented.
- Resume upload validates extension and size but does not inspect file signatures. Add malware scanning and stricter content checks for public deployment.
- CORS, HTTPS termination, reverse-proxy limits, secret rotation/backup, operational monitoring, password reset, email change, and administrative account recovery need deployment decisions.
- Existing anonymous resume rows have `user_id IS NULL`; they remain preserved but are not visible in user-owned routes.
- The PostgreSQL-backed registration-to-resume flow passed against the separate test database. Broader concurrency behavior and real provider delivery remain unverified.
