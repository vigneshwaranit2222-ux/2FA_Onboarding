# Multi-Channel OTP API Documentation

This document describes the API contracts, request payloads, response structures, and security considerations for the Multi-Channel OTP verification endpoints in the AI Resume Onboarding service.

Base URL prefix: `/api/v1/auth`

---

## 1. Endpoints Overview

| Method | Endpoint | Auth Required | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/auth/email/send-otp` | No | Request an email verification code |
| `POST` | `/api/v1/auth/email/verify-otp` | No | Verify an email verification code |
| `POST` | `/api/v1/auth/whatsapp/send-otp` | No | Request a WhatsApp phone verification code |
| `POST` | `/api/v1/auth/whatsapp/verify-otp` | No | Verify a WhatsApp phone verification code |

---

## 2. Detailed Endpoint Specifications

### 2.1 Request Email OTP
* **Endpoint:** `POST /api/v1/auth/email/send-otp`
* **Status Code:** `202 Accepted`
* **Request Header:** `Content-Type: application/json`
* **Request Body:**
```json
{
  "email": "user@example.com"
}
```
* **Success Response (202 Accepted):**
```json
{
  "success": true,
  "message": "If the account is eligible, the verification message was accepted for processing.",
  "channel": "email",
  "expires_in_seconds": 300
}
```
* **Security & Enumeration Defense:**
  * Returns generic `202 Accepted` whether the account is registered or not, preventing email enumeration.
  * If the account is already email-verified, the endpoint quietly returns `202 Accepted` without sending an OTP.
  * If the request is within cooldown or exceeds max resends, it returns `202 Accepted` without generating extra provider calls.
* **Error Responses:**
  * `422 Unprocessable Entity`: Malformed email address.
  * `502 Bad Gateway`: SMTP delivery refused by upstream provider.
  * `503 Service Unavailable`: SMTP configuration missing on server.

---

### 2.2 Verify Email OTP
* **Endpoint:** `POST /api/v1/auth/email/verify-otp`
* **Status Code:** `200 OK`
* **Request Body:**
```json
{
  "email": "user@example.com",
  "code": "123456"
}
```
* **Success Response (200 OK):**
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
* **Business Logic:**
  * Checks matching active challenge for `user_id`, `channel='email'`, and `purpose='email_verification'`.
  * Verifies expiration (`expires_at > now`).
  * Verifies attempt limit (`attempts < OTP_MAX_ATTEMPTS`).
  * Constant-time HMAC comparison.
  * Marks challenge `is_verified = True` and records `verified_at`.
  * Sets `user.email_verified = True`.
  * Re-evaluates `user.is_verified = bool(email_verified and phone_verified)`.
* **Error Responses:**
  * `400 Bad Request`: Code is invalid, expired, already verified, or max attempts exceeded.
    ```json
    {
      "detail": "Verification code is invalid or expired"
    }
    ```
  * `422 Unprocessable Entity`: Code is not 4-10 digits.

---

### 2.3 Request WhatsApp OTP
* **Endpoint:** `POST /api/v1/auth/whatsapp/send-otp`
* **Status Code:** `202 Accepted`
* **Request Body:**
```json
{
  "phone": "+14155552671"
}
```
* **Validation Rules:**
  * Must be international E.164 format (`+[country_code][number]`, between 9 and 24 characters).
  * Automatically normalizes spaces, dashes, and parentheses.
* **Success Response (202 Accepted):**
```json
{
  "success": true,
  "message": "If the account is eligible, the verification message was accepted for processing.",
  "channel": "whatsapp",
  "expires_in_seconds": 300
}
```
* **Error Responses:**
  * `422 Unprocessable Entity`: Invalid phone format.
  * `502 Bad Gateway`: Meta Cloud API provider error.
  * `503 Service Unavailable`: WhatsApp credentials unconfigured.

---

### 2.4 Verify WhatsApp OTP
* **Endpoint:** `POST /api/v1/auth/whatsapp/verify-otp`
* **Status Code:** `200 OK`
* **Request Body:**
```json
{
  "phone": "+14155552671",
  "code": "654321"
}
```
* **Success Response (200 OK):**
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
* **Business Logic:**
  * Checks matching active challenge for `user_id`, `channel='whatsapp'`, and `purpose='phone_verification'`.
  * Marks challenge `is_verified = True`.
  * Sets `user.phone_verified = True`.
  * If both `email_verified` and `phone_verified` are now `True`:
    * Sets `user.is_verified = True`
    * Sets `user.is_active = True`
    * Account becomes eligible for login.
* **Error Responses:**
  * `400 Bad Request`: Code invalid, expired, or attempts exhausted.
  * `422 Unprocessable Entity`: Malformed phone or code.

---

## 3. Account Verification State Machine

```
   [User Registers]
          |
          v
   +------------------------------------------------------+
   | is_verified: false, is_active: false                 |
   | email_verified: false, phone_verified: false         |
   +------------------------------------------------------+
          |
          | POST /auth/email/verify-otp
          v
   +------------------------------------------------------+
   | is_verified: false, is_active: false                 |
   | email_verified: true,  phone_verified: false         |
   +------------------------------------------------------+
          |
          | POST /auth/whatsapp/verify-otp
          v
   +------------------------------------------------------+
   | is_verified: true,  is_active: true                  |
   | email_verified: true,  phone_verified: true          |
   | -> User can now authenticate via /auth/login         |
   +------------------------------------------------------+
```

