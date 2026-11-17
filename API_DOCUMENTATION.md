# API documentation

All routes are registered in FastAPI OpenAPI and Swagger at `/docs`. Protected routes require `Authorization: Bearer <access_token>`.

## Registration and authentication

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/auth/register` | No | Create an inactive account. Request: `full_name`, `email`, E.164 `phone`, `password`, `confirm_password`. Returns safe user fields only. |
| POST | `/api/v1/auth/login` | No | Request: `email`, `password`, plus `totp_code` or `recovery_code` when TOTP is enabled. Issues access and refresh tokens only after all required factors pass. |
| POST | `/api/v1/auth/refresh` | Refresh token | Request: `refresh_token`. Rotates it and returns a new token pair. |
| POST | `/api/v1/auth/logout` | Yes | Request: `refresh_token`. Revokes its session family; access tokens from that family stop passing authentication. |
| GET | `/api/v1/auth/me` | Yes | Return the authenticated profile and verification state. |
| PATCH | `/api/v1/auth/me` | Yes | Update `full_name` and/or `phone`. A changed phone requires re-verification and revokes existing sessions. Email is not editable here. |

## Email and WhatsApp verification

| Method | Path | Auth | Request |
|---|---|---|---|
| POST | `/api/v1/auth/email/send-otp` | No | `{"email":"user@example.com"}` |
| POST | `/api/v1/auth/email/verify-otp` | No | `{"email":"user@example.com","code":"123456"}` |
| POST | `/api/v1/auth/whatsapp/send-otp` | No | `{"phone":"+14155552671"}` |
| POST | `/api/v1/auth/whatsapp/verify-otp` | No | `{"phone":"+14155552671","code":"123456"}` |

Send responses are generic to reduce account enumeration. `202` means the request was accepted for processing; it is not proof that the message arrived. Missing provider configuration returns `503`; provider rejection returns `502`. Invalid, expired, and reused codes return a generic `400`.

## TOTP

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/auth/totp/setup` | Yes | Returns a provisioning URI and QR data URI once for pending enrollment. |
| POST | `/api/v1/auth/totp/verify` | Yes | Request `{"code":"123456"}` to enable TOTP. Returns ten one-time recovery codes. |
| POST | `/api/v1/auth/totp/disable` | Yes | Request a current password and exactly one of `code` or `recovery_code`. |

## Profile and resumes

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/resume/parse` | Yes | Upload a PDF or DOCX; the saved resume is associated with the authenticated user. |
| GET | `/api/v1/users/me/resumes` | Yes | List the authenticated user's resumes. |
| GET | `/api/v1/users/me/resumes/{resume_id}` | Yes | View extracted data and text for an owned resume. |
| PATCH | `/api/v1/users/me/resumes/{resume_id}` | Yes | Correct extracted `full_name`, `email`, `phone`, `skills`, or `experience` for an owned resume. |
| GET | `/api/v1/users/me/resumes/{resume_id}/file` | Yes | Download the owned resume after a storage-root check. |

## Status and common errors

- `201`: registration created.
- `200`: login, verification, TOTP, profile, and resume operations succeeded.
- `202`: OTP request accepted for provider processing.
- `400`: invalid verification code or malformed workflow state.
- `401`: invalid credentials, token, or unauthenticated request.
- `409`: duplicate registration, already-enabled TOTP, or conflicting account state.
- `413`: resume exceeds the upload limit.
- `422`: Pydantic request validation failed.
- `429`: TOTP verification lockout.
- `502`/`503`: delivery provider rejected a message or is not configured.
- `404`: resume does not exist or is not owned by the authenticated user.
