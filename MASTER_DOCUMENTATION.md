# AI-Powered Resume Parser & Multi-Channel 2FA Onboarding Pipeline
# Complete Master Engineering Documentation

> **Project Location:** `C:\GTM\resume_onboarding`  
> **Technology Stack:** Python 3.11+, FastAPI, PostgreSQL, SQLAlchemy 2.0 Async ORM, asyncpg, Pydantic v2, Alembic, Argon2id, PyJWT, pyotp, SMTP, Meta WhatsApp Cloud API, Pytest, HTTPX, pdfplumber, python-docx  
> **Documentation Version:** Consolidated Master (Days 1 – 3)

---

## Table of Contents

1. [Project Overview & System Architecture](#1-project-overview--system-architecture)
2. [Local Setup, Environment & Running the Server](#2-local-setup-environment--running-the-server)
3. [Database Architecture & Migration Guide](#3-database-architecture--migration-guide)
4. [Day 3 Implementation: Multi-Channel OTP Verification System](#4-day-3-implementation-multi-channel-otp-verification-system)
5. [Complete API Documentation & Endpoint Reference](#5-complete-api-documentation--endpoint-reference)
6. [Security Architecture, Threat Modeling & Audit Report](#6-security-architecture-threat-modeling--audit-report)
7. [QA Automation, Testing & Regression Report](#7-qa-automation-testing--regression-report)

---

## 1. Project Overview & System Architecture

The **AI-Powered Resume Parser & Multi-Channel 2FA Onboarding Pipeline** is a modular FastAPI backend delivering secure user registration, multi-channel two-factor onboarding verification (Email OTP via SMTP and WhatsApp OTP via Meta Cloud API), authenticator-based TOTP multi-factor authentication, rotating refresh-token session management, and authenticated resume parsing and storage for PDF and DOCX documents.

### High-Level Architectural Flow

```
+---------------------------------------------------------------------------------------------------+
|                                        FastAPI Application                                        |
+---------------------------------------------------------------------------------------------------+
      |                        |                                |                        |
      v                        v                                v                        v
+------------+        +------------------+             +------------------+        +------------+
| Auth Route |        | Email OTP Route  |             | WhatsApp Route   |        | Resume API |
|  Register  |        | /email/send-otp  |             | /whatsapp/send   |        |  /parse    |
|   Login    |        | /email/verify    |             | /whatsapp/verify |        |  /resumes  |
+-----+------+        +--------+---------+             +--------+---------+        +-----+------+
      |                        |                                |                        |
      +------------------------+---------------+----------------+                        |
                                               |                                         |
                                     +---------v----------+                              |
                                     |    OTP Service     |                              |
                                     |  Keyed HMAC-SHA256 |                              |
                                     |   Secrets CSPRNG   |                              |
                                     +----+----------+----+                              |
                                          |          |                                   |
                         +----------------+          +----------------+                  |
                         v                                            v                  v
                 +---------------+                            +---------------+   +--------------+
                 | SMTP Service  |                            | WhatsApp Prov |   | Resume Parser|
                 | HTML + Text   |                            | Meta Graph API|   | docx/pdfplumber
                 +-------+-------+                            +-------+-------+   +-------+------+
                         |                                            |                   |
                         +---------------------+----------------------+                   |
                                               |                                          |
                                     +---------v----------+                               |
                                     |  Async SQLAlchemy  | <-----------------------------+
                                     |   PostgreSQL DB    |
                                     +--------------------+
```

### Component Responsibilities

1. **Registration Service (`app/services/registration_service.py`):**
   * Creates accounts in an inactive, unverified state (`is_verified = False`, `is_active = False`).
   * Validates name, normalized lowercase email, international E.164 phone format, and password complexity.
   * Hashes passwords asynchronously using Argon2id with memory-hard parameters.
2. **OTP Core Service (`app/services/otp_service.py`):**
   * Generates cryptographically secure 6-digit numeric OTPs via `secrets.randbelow`.
   * Computes keyed HMAC-SHA256 digests binding `user_id`, `purpose`, and `code`.
   * Verifies hashes in constant time via `hmac.compare_digest`.
   * Enforces attempt limits (`OTP_MAX_ATTEMPTS=5`), expiration (`OTP_EXPIRE_MINUTES=5`), resend cooldowns (`OTP_RESEND_COOLDOWN_SECONDS=60`), and resend count limits (`OTP_MAX_RESENDS=3`).
3. **Email Delivery Service (`app/services/email_service.py`):**
   * Formats dual-layer multipart MIME messages: formatted plain text fallback + accessible HTML template.
   * Dispatches via STARTTLS (port 587) or SSL (port 465) with configurable `SMTP_TIMEOUT`.
   * Handles delivery errors and triggers database rollbacks to prevent orphan unverified challenges.
4. **WhatsApp Delivery Service (`app/services/whatsapp_service.py`):**
   * Implements `WhatsAppOTPProvider` protocol.
   * `MetaWhatsAppCloudProvider`: Formats pre-approved authentication template payloads to Meta Graph API.
   * `MockWhatsAppProvider`: In-memory message capture for offline local development and CI/CD pipelines.
5. **Token & Session Service (`app/services/token_service.py`):**
   * Issues short-lived JWT access tokens bound to active session families.
   * Manages opaque refresh tokens stored as SHA-256 hashes with automatic family rotation and reuse detection.
6. **Resume Parser (`app/services/resume_parser.py`):**
   * Extracts text and structured entities (name, email, phone, skills, experience) from PDF and DOCX files.
   * Enforces user ownership and upload directory security boundaries.

---

## 2. Local Setup, Environment & Running the Server

### Prerequisites
* Python 3.11+
* PostgreSQL 14+ running on port 5432
* PowerShell on Windows (or Bash on Linux/macOS)

### 2.1 Virtual Environment & Installation

```powershell
# Navigate to project root
cd C:\GTM\resume_onboarding

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install requirements
python -m pip install -r requirements.txt

# Verify dependency consistency
python -m pip check
```

### 2.2 Environment Configuration (`.env`)

Copy `.env.example` to `.env` and configure keys. **Never commit `.env` to source control.**

```ini
# Application Database URL
DATABASE_URL=postgresql+asyncpg://postgres:PASSWORD@localhost:5432/resume_onboarding

# Dedicated PostgreSQL Test Database URL (for integration tests)
TEST_DATABASE_URL=postgresql+asyncpg://postgres:PASSWORD@localhost:5432/resume_onboarding_test

# JWT Signing and Lifetime
JWT_SECRET_KEY=replace-with-a-random-secret-at-least-32-characters-long
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# OTP Protection & Lifecycle
OTP_HASH_SECRET=replace-with-a-separate-random-secret-at-least-32-characters
OTP_LENGTH=6
OTP_EXPIRE_MINUTES=5
OTP_TTL_SECONDS=300
OTP_RESEND_COOLDOWN_SECONDS=60
OTP_MAX_ATTEMPTS=5
OTP_MAX_RESENDS=3

# SMTP Email Delivery (STARTTLS or SSL)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-smtp-user
SMTP_PASSWORD=your-smtp-password
SMTP_FROM_EMAIL=no-reply@yourdomain.com
SMTP_STARTTLS=true
SMTP_USE_SSL=false
SMTP_TIMEOUT=10

# WhatsApp Provider Configuration (Meta Cloud API or Mock)
WHATSAPP_PROVIDER=meta
WHATSAPP_API_URL=https://graph.facebook.com
WHATSAPP_API_TOKEN=your-meta-bearer-token
WHATSAPP_PHONE_NUMBER_ID=your-meta-phone-number-id
WHATSAPP_OTP_TEMPLATE=your-preapproved-auth-template
WHATSAPP_API_VERSION=v20.0
WHATSAPP_TEMPLATE_LANGUAGE=en
WHATSAPP_TIMEOUT=10

# TOTP Authenticator (Fernet 32-byte url-safe base64 key)
TOTP_ENCRYPTION_KEY=replace-with-a-Fernet-generated-key
TOTP_ISSUER=Resume Onboarding
```

### 2.3 Running the Application

```powershell
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

* **Interactive Swagger UI:** `http://127.0.0.1:8000/docs`
* **OpenAPI JSON Spec:** `http://127.0.0.1:8000/openapi.json`
* **Health Check Endpoint:** `http://127.0.0.1:8000/health`
* **Root Endpoint:** `http://127.0.0.1:8000/`

---

## 3. Database Architecture & Migration Guide

### 3.1 Database Schema Reference

The PostgreSQL database `resume_onboarding` contains five primary tables:

```
+--------------------------------------------------------------------------------------------------+
|                                              users                                               |
+--------------------------------------------------------------------------------------------------+
| id                     | INTEGER PRIMARY KEY AUTO-INCREMENT                                      |
| full_name              | VARCHAR(150) NOT NULL                                                   |
| email                  | VARCHAR(255) NOT NULL UNIQUE (indexed)                                  |
| phone                  | VARCHAR(20) NULL UNIQUE                                                 |
| password_hash          | VARCHAR(255) NULL (Argon2id)                                            |
| email_verified         | BOOLEAN NOT NULL DEFAULT FALSE                                          |
| phone_verified         | BOOLEAN NOT NULL DEFAULT FALSE                                          |
| totp_enabled           | BOOLEAN NOT NULL DEFAULT FALSE                                          |
| totp_secret_encrypted  | TEXT NULL (Fernet AES-128-CBC)                                          |
| totp_confirmed_at      | TIMESTAMPTZ NULL                                                        |
| totp_last_used_step    | BIGINT NULL (Replay prevention)                                         |
| totp_failed_attempts   | INTEGER NOT NULL DEFAULT 0                                              |
| totp_locked_until      | TIMESTAMPTZ NULL                                                        |
| totp_recovery_codes    | JSONB NOT NULL DEFAULT '[]'::jsonb                                      |
| failed_login_attempts  | INTEGER NOT NULL DEFAULT 0                                              |
| login_locked_until     | TIMESTAMPTZ NULL                                                        |
| is_verified            | BOOLEAN DEFAULT FALSE (email_verified AND phone_verified)                |
| is_active              | BOOLEAN DEFAULT FALSE                                                   |
| created_at             | TIMESTAMPTZ DEFAULT now()                                               |
+--------------------------------------------------------------------------------------------------+

+--------------------------------------------------------------------------------------------------+
|                                          otp_challenges                                          |
+--------------------------------------------------------------------------------------------------+
| id                     | INTEGER PRIMARY KEY AUTO-INCREMENT                                      |
| user_id                | INTEGER NOT NULL REFERENCES users(id)                                   |
| channel                | VARCHAR(30) NOT NULL ('email' | 'whatsapp')                             |
| purpose                | VARCHAR(50) NOT NULL ('email_verification' | 'phone_verification')      |
| otp_hash               | VARCHAR(255) NOT NULL (HMAC-SHA256)                                     |
| expires_at             | TIMESTAMPTZ NOT NULL                                                    |
| is_verified            | BOOLEAN DEFAULT FALSE                                                   |
| attempts               | INTEGER NOT NULL DEFAULT 0                                              |
| resend_count           | INTEGER NOT NULL DEFAULT 0                                              |
| last_sent_at           | TIMESTAMPTZ NOT NULL DEFAULT now()                                      |
| verified_at            | TIMESTAMPTZ NULL                                                        |
| created_at             | TIMESTAMPTZ DEFAULT now()                                               |
| INDEX                  | ix_otp_user_channel_purpose_created (user_id, channel, purpose, created)|
+--------------------------------------------------------------------------------------------------+

+--------------------------------------------------------------------------------------------------+
|                                          refresh_tokens                                          |
+--------------------------------------------------------------------------------------------------+
| id                     | INTEGER PRIMARY KEY AUTO-INCREMENT                                      |
| user_id                | INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE                 |
| family_id              | VARCHAR(36) NOT NULL (UUID session family)                              |
| token_hash             | VARCHAR(64) NOT NULL UNIQUE (SHA-256)                                    |
| expires_at             | TIMESTAMPTZ NOT NULL                                                    |
| created_at             | TIMESTAMPTZ NOT NULL DEFAULT now()                                      |
| revoked_at             | TIMESTAMPTZ NULL                                                        |
| replaced_by_token_id   | INTEGER NULL REFERENCES refresh_tokens(id)                              |
+--------------------------------------------------------------------------------------------------+

+--------------------------------------------------------------------------------------------------+
|                                           user_resumes                                           |
+--------------------------------------------------------------------------------------------------+
| id                     | INTEGER PRIMARY KEY AUTO-INCREMENT                                      |
| user_id                | INTEGER NULL REFERENCES users(id) (NULL for Day 1 baseline resume)      |
| file_name              | VARCHAR(255) NOT NULL                                                   |
| file_path              | VARCHAR(500) NULL                                                       |
| extracted_text         | TEXT NULL                                                               |
| extracted_data         | JSONB NULL (Extracted skills, experience, contact details)              |
| created_at             | TIMESTAMPTZ DEFAULT now()                                               |
+--------------------------------------------------------------------------------------------------+
```

### 3.2 Alembic Migration History & Safety Plan

* **Alembic Revisions:**
  * `0001_day1`: Baseline schema containing `users`, `user_resumes`, and initial `otp_challenges`.
  * `0002_auth`: Authentication revision adding verification flags, TOTP columns, OTP purpose, resend counters, timestamp tracking, composite indexes, and the `refresh_tokens` table.
* **Migration Status:** The production database is stamped at `0002_auth`.
* **Data Preservation:**
  * The historical resume uploaded during Day 1 has `user_id = NULL`. It is strictly preserved and remains readable.
  * A full binary custom-format backup exists at `backups/resume_onboarding_pre_phase6_20261113.dump`.
* **Testing Policy:** Test suites never execute destructive migrations or table resets against `resume_onboarding`. Dedicated integration testing runs against `resume_onboarding_test`.

---

## 4. Day 3 Implementation: Multi-Channel OTP Verification System

### 4.1 Cryptographic OTP Generation & Storage

1. **Entropy & Generation:**
   OTPs are generated using Python's `secrets` module (`secrets.randbelow(10**length)`), ensuring cryptographic randomness. Leading zeros are preserved through formatting syntax:
   ```python
   def generate_otp(length: int | None = None) -> str:
       effective_length = length or get_otp_length()
       max_value = 10**effective_length
       return f"{secrets.randbelow(max_value):0{effective_length}d}"
   ```
2. **Keyed HMAC-SHA256 Storage:**
   Storing short numeric OTPs in plain SHA-256 makes them susceptible to offline rainbow-table recovery. Our implementation uses a keyed HMAC with a high-entropy secret (`OTP_HASH_SECRET`) stored strictly in the environment, context-bound to the user and purpose:
   ```python
   def hash_otp(code: str, user_id: int, purpose: str) -> str:
       message = f"{user_id}:{purpose}:{code}".encode("utf-8")
       return hmac.new(_otp_secret(), message, hashlib.sha256).hexdigest()
   ```
3. **Constant-Time Verification:**
   Verification uses `hmac.compare_digest` to prevent statistical side-channel timing attacks.

### 4.2 Account Verification Policy

* **Dual-Channel Rule:** Both Email and WhatsApp verifications are mandatory.
* **Account Activation State:**
  ```python
  user.email_verified = True  # upon email OTP verification
  user.phone_verified = True  # upon WhatsApp OTP verification
  user.is_verified = bool(user.email_verified and user.phone_verified)
  user.is_active = user.is_verified
  ```
* **Authentication Gate:** The `/login` endpoint verifies that `user.is_active` and `user.is_verified` are `True`. Unverified accounts are rejected with `HTTP 401 Unauthorized`.

### 4.3 Email Delivery Service (SMTP)
* **Protocol Support:** STARTTLS (default port 587) or SSL (port 465).
* **MIME Structure:** Multipart MIME message containing:
  * Plain text fallback: `"Your verification code is {code}. It expires in {ttl_minutes} minutes..."`
  * Responsive HTML template: Clean, accessible email body styled with card layout and high-visibility verification code block.
* **Asynchronous Threading:** Uses `asyncio.to_thread` for non-blocking I/O operations.
* **Transaction Rollback:** Upstream SMTP exceptions (`smtplib.SMTPException`, socket timeouts) raise `OTPDeliveryError`, triggering a database rollback so no unverified challenge record is orphaned.

### 4.4 WhatsApp Delivery Service (Meta Cloud API)
* **Provider Abstraction:** Implements the `WhatsAppOTPProvider` protocol.
* **Meta Cloud API Client:** Dispatches authentication templates via HTTPS POST to `https://graph.facebook.com/{api_version}/{phone_number_id}/messages` with pre-approved template name, parameters, and Bearer token.
* **Mock WhatsApp Provider:** Provides in-memory test capability when `WHATSAPP_PROVIDER=mock`, preventing unnecessary external calls during development and CI.

---

## 5. Complete API Documentation & Endpoint Reference

### 5.1 Registration & Authentication Endpoints

#### 1. Register Account
* **`POST /api/v1/auth/register`**
* **Status:** `201 Created`
* **Request:**
  ```json
  {
    "full_name": "Ada Lovelace",
    "email": "ada@example.com",
    "phone": "+14155552671",
    "password": "StrongPassword123!",
    "confirm_password": "StrongPassword123!"
  }
  ```
* **Response:**
  ```json
  {
    "user": {
      "id": 1,
      "full_name": "Ada Lovelace",
      "email": "ada@example.com",
      "phone": "+14155552671",
      "email_verified": false,
      "phone_verified": false,
      "is_verified": false,
      "is_active": false,
      "totp_enabled": false,
      "created_at": "2026-11-16T09:00:00Z"
    },
    "message": "Registration successful. Verify your email and phone to activate your account."
  }
  ```

#### 2. Authenticate & Obtain Tokens
* **`POST /api/v1/auth/login`**
* **Status:** `200 OK`
* **Request:**
  ```json
  {
    "email": "ada@example.com",
    "password": "StrongPassword123!",
    "totp_code": null,
    "recovery_code": null
  }
  ```
* **Response:**
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "a1b2c3d4...",
    "token_type": "bearer",
    "expires_in": 900
  }
  ```

#### 3. Rotate Refresh Token
* **`POST /api/v1/auth/refresh`**
* **Status:** `200 OK`
* **Request:** `{"refresh_token": "a1b2c3d4..."}`
* **Response:** New access token and rotated refresh token.

#### 4. Revoke Session (Logout)
* **`POST /api/v1/auth/logout`**
* **Status:** `200 OK`
* **Headers:** `Authorization: Bearer <access_token>`
* **Request:** `{"refresh_token": "a1b2c3d4..."}`
* **Response:** `{"message": "Session revoked"}`

#### 5. Authenticated Profile
* **`GET /api/v1/auth/me`**
* **Status:** `200 OK`
* **Headers:** `Authorization: Bearer <access_token>`
* **Response:** Returns `UserProfile` schema.

#### 6. Update Profile
* **`PATCH /api/v1/auth/me`**
* **Status:** `200 OK`
* **Headers:** `Authorization: Bearer <access_token>`
* **Request:** `{"full_name": "Ada Byron", "phone": "+14155559999"}`
* **Behavior:** Updating phone number resets `phone_verified = False`, `is_verified = False`, `is_active = False` and revokes active sessions.

---

### 5.2 Multi-Channel OTP Endpoints

#### 1. Request Email OTP
* **`POST /api/v1/auth/email/send-otp`**
* **Status:** `202 Accepted`
* **Request:**
  ```json
  {
    "email": "ada@example.com"
  }
  ```
* **Response:**
  ```json
  {
    "success": true,
    "message": "If the account is eligible, the verification message was accepted for processing.",
    "channel": "email",
    "expires_in_seconds": 300
  }
  ```

#### 2. Verify Email OTP
* **`POST /api/v1/auth/email/verify-otp`**
* **Status:** `200 OK`
* **Request:**
  ```json
  {
    "email": "ada@example.com",
    "code": "123456"
  }
  ```
* **Response:**
  ```json
  {
    "success": true,
    "verified": true,
    "message": "Email verified successfully",
    "email_verified": true,
    "phone_verified": false,
    "is_verified": false
  }
  ```

#### 3. Request WhatsApp OTP
* **`POST /api/v1/auth/whatsapp/send-otp`**
* **Status:** `202 Accepted`
* **Request:**
  ```json
  {
    "phone": "+14155552671"
  }
  ```
* **Response:**
  ```json
  {
    "success": true,
    "message": "If the account is eligible, the verification message was accepted for processing.",
    "channel": "whatsapp",
    "expires_in_seconds": 300
  }
  ```

#### 4. Verify WhatsApp OTP
* **`POST /api/v1/auth/whatsapp/verify-otp`**
* **Status:** `200 OK`
* **Request:**
  ```json
  {
    "phone": "+14155552671",
    "code": "654321"
  }
  ```
* **Response:**
  ```json
  {
    "success": true,
    "verified": true,
    "message": "Phone verified successfully",
    "email_verified": true,
    "phone_verified": true,
    "is_verified": true
  }
  ```

---

### 5.3 Authenticator TOTP Endpoints

* **`POST /api/v1/auth/totp/setup`** (Auth required): Returns provisioning URI (`otpauth://...`) and QR code data URI once for enrollment.
* **`POST /api/v1/auth/totp/verify`** (Auth required): Validates a 6-digit TOTP code, enables TOTP, and returns 10 single-use emergency recovery codes.
* **`POST /api/v1/auth/totp/disable`** (Auth required): Disables TOTP requiring password confirmation plus an active TOTP code or recovery code.

---

### 5.4 Resume Parsing Endpoints

* **`POST /api/v1/resume/parse`** (Auth required): Uploads a PDF or DOCX file (up to 10MB), extracts text, extracts structured JSON entities (skills, experience, contact details), and persists ownership under the authenticated user.
* **`GET /api/v1/users/me/resumes`** (Auth required): Lists all resumes owned by the authenticated user.
* **`GET /api/v1/users/me/resumes/{resume_id}`** (Auth required): Retrieves extracted text and structured data for an owned resume.
* **`PATCH /api/v1/users/me/resumes/{resume_id}`** (Auth required): Corrects extracted fields (full name, email, phone, skills, experience).
* **`GET /api/v1/users/me/resumes/{resume_id}/file`** (Auth required): Downloads the original uploaded resume file with secure storage boundary checks.

---

## 6. Security Architecture, Threat Modeling & Audit Report

### 6.1 Threat Mitigation Matrix

| Threat | Attack Vector | Security Countermeasure |
|---|---|---|
| **OTP Brute Force** | Exhausting 6-digit combinations ($10^6$) | `OTP_MAX_ATTEMPTS=5` lockouts; attempt counter incremented on every failure. |
| **Offline Rainbow Table** | Database dump leak containing OTP hashes | Keyed HMAC-SHA256 using `OTP_HASH_SECRET` outside database; context bound to `user_id` and `purpose`. |
| **Timing Attacks** | Remote side-channel analysis of byte equality checks | Constant-time string comparison via `hmac.compare_digest`. |
| **OTP Expiration Replay** | Submitting OTP after validity window | Expiration timestamps checked using timezone-aware UTC (`datetime.now(timezone.utc)`). |
| **Resend Flooding** | DoS against SMTP / Meta WhatsApp APIs | `OTP_RESEND_COOLDOWN_SECONDS=60` and `OTP_MAX_RESENDS=3` enforced via atomic DB row locks (`with_for_update()`). |
| **Cross-User Injection** | Attacker verifying account using victim's OTP | Digest computation explicitly includes target `user_id`; verification against another user is rejected. |
| **Cross-Factor Bypass** | Using Email OTP to satisfy Phone verification | Digest binds `purpose` (`email_verification` vs `phone_verification`); purposes cannot cross-validate. |
| **Replay Attacks** | Re-submitting valid OTP after verification | Verified challenges are flagged `is_verified = True` and timestamped; subsequent verification attempts fail immediately. |
| **Account Enumeration** | Probing endpoint to discover registered emails/phones | Generic `202 Accepted` response returned regardless of account existence or verification status. |
| **Credential Leakage** | Credentials appearing in log files | SQL echo disabled (`echo=False`); plaintext OTPs, JWT secrets, and DB passwords strictly forbidden in loggers. |

---

## 7. QA Automation, Testing & Regression Report

### 7.1 Test Suite Summary

* **Total Automated Tests:** 89
* **Passed:** 89 (100%)
* **Failed:** 0
* **Skipped:** 0
* **Test Suite Duration:** ~5.26 seconds

### 7.2 Test Coverage by Module

1. **OTP Cryptography (`tests/test_otp_generation.py`):** 6 tests covering 6-digit generation, zero padding preservation, configurable lengths (4-10 digits), validation bounds, HMAC-SHA256 hashing, and constant-time comparison.
2. **Email OTP Lifecycle (`tests/test_email_otp.py`):** 4 tests covering challenge issuance, hash persistence, verification, plain text + HTML email template rendering, and delivery failure rollback.
3. **WhatsApp OTP Lifecycle (`tests/test_whatsapp_otp.py`):** 4 tests covering in-memory mock provider, E.164 phone validation, dual-channel verification completion, and provider failure rollback.
4. **Expiration & TTL (`tests/test_otp_expiration.py`):** 3 tests validating `OTP_EXPIRE_MINUTES`, `OTP_TTL_SECONDS`, rejection of expired codes, and re-issuance after expiration.
5. **Attempt Limits (`tests/test_otp_attempts.py`):** 2 tests verifying attempt counter increments on failure and permanent lockout upon reaching max attempts.
6. **Resend Cooldown & Limits (`tests/test_otp_resend.py`):** 3 tests validating cooldown blocking within 60s, code renewal after cooldown, and blocking when max resends (3) are exceeded.
7. **Security Controls (`tests/test_otp_security.py`):** 4 tests verifying zero plaintext OTP storage, cross-user attack rejection, cross-purpose attack rejection, and post-verification replay rejection.
8. **End-to-End Registration Flow (`tests/test_registration_verification.py`):** 1 comprehensive end-to-end multi-channel user onboarding test.
9. **PostgreSQL E2E Integration (`tests/test_postgres_end_to_end.py`):** 1 live integration test executing registration, Email OTP verification, WhatsApp OTP verification, TOTP setup, session rotation, and resume upload against `resume_onboarding_test`.
10. **Resume Parser Regression (`tests/test_resume_parser_regression.py` & related):** 7 tests validating DOCX and PDF parsing, JSON entity extraction, upload authorization, and storage isolation.
11. **Authentication, JWT & TOTP Suites:** 48 tests covering Argon2id hashing, token rotation, reuse detection, logout, TOTP QR setup, recovery code consumption, and lockout.

### 7.3 Final Feature & Provider Status

| Capability | Status | Validation Method |
|---|---|---|
| Secure Numeric OTP Generation | **PASS** | Automated CSPRNG tests |
| Keyed HMAC-SHA256 OTP Storage | **PASS** | Unit & cryptographic tests |
| Email OTP Lifecycle (Send & Verify) | **PASS** | Automated mock SMTP tests |
| WhatsApp OTP Lifecycle (Send & Verify) | **PASS** | Automated mock provider tests |
| Real SMTP Email Delivery | **BLOCKED** | Pending production SMTP host credentials |
| Real Meta WhatsApp API Delivery | **BLOCKED** | Pending Meta Business API token & Phone ID |
| OTP Expiration & Attempt Limits | **PASS** | Automated test suite |
| Resend Cooldown & Limits | **PASS** | Automated test suite |
| Replay & Cross-Factor Prevention | **PASS** | Automated test suite |
| Dual-Channel Verification Policy | **PASS** | Automated test suite |
| PostgreSQL End-to-End Integration | **PASS** | Executed against `resume_onboarding_test` |
| Resume Parser Regression | **PASS** | Verified DOCX / PDF extraction |

