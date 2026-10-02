# DRF-TOTP

TOTP (Time-based One-Time Password, RFC 6238) second-factor authentication for
Django REST Framework: enrollment with any authenticator app, code validation
with replay protection and rate limiting, backup codes, optional encryption of
secrets at rest, and permission classes to enforce the second factor on your
own views.

[![CI](https://github.com/mohamed-alired/drf-totp/actions/workflows/ci.yml/badge.svg)](https://github.com/mohamed-alired/drf-totp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/drf-totp.svg)](https://pypi.org/project/drf-totp/)

## Features

- Generate a secret and `otpauth://` provisioning URI (render it as a QR code on the client)
- Confirm enrollment with the first code from the app
- Validate codes with drift tolerance and replay protection (a code is accepted once)
- Per-user throttling on every token endpoint, with an optional hard lockout
- Hashed, single-use backup codes for account recovery
- Disable requires a valid code (optionally the password too)
- `IsTOTPVerified` / `IsTOTPEnrolled` permissions to gate your views
- Optional Fernet encryption of secrets at rest, with key rotation
- Signals, logging and a read-only admin that never shows the secret
- Django 4.2 – 5.2, Python 3.9 – 3.13, DRF 3.14+

## Installation

```bash
pip install drf-totp
# with encryption of secrets at rest:
pip install "drf-totp[encryption]"
```

```python
# settings.py
INSTALLED_APPS = [
    ...
    "rest_framework",
    "drf_totp",
]

TOTP_ISSUER_NAME = "Your App Name"   # shown in the authenticator app
```

```python
# urls.py
urlpatterns = [
    ...
    path("auth/", include("drf_totp.urls")),
]
```

```bash
python manage.py migrate
```

All endpoints require an authenticated user (`IsAuthenticated`), using whatever
authentication classes your DRF settings define.

## How it works

### Enrollment

```
Client                                  Server
  │  POST /auth/otp/generate/             │
  │──────────────────────────────────────▶│  create secret (unverified)
  │  { secret, otpauth_url }              │
  │◀──────────────────────────────────────│
  │  show QR code, user scans it          │
  │  POST /auth/otp/verify/ {token}       │
  │──────────────────────────────────────▶│  code ok → otp_verified = True
  │  { detail: "TOTP verified…" }         │
  │◀──────────────────────────────────────│
  │  POST /auth/otp/backup-codes/ {token} │
  │──────────────────────────────────────▶│  issue 10 single-use codes
  │  { backup_codes: [...] }              │  (show once, user stores them)
  │◀──────────────────────────────────────│
```

The secret is returned **only** by `/generate/`. `/status/` never includes it.

### Login with a second factor

```
1. Password login (your existing flow)         → session / token
2. GET  /auth/otp/status/                       → otp_verified: true?
3. POST /auth/otp/validate/ {token}             → 200 "Token is valid"
4. Your protected views use IsTOTPVerified      → allowed
```

Step 4 is yours to wire up: drf-totp validates codes, it does not intercept
requests. See [Enforcing the second factor](#enforcing-the-second-factor).

### Disable

```
POST /auth/otp/disable/ {token}   # a TOTP code or a backup code
```

## API

All responses are JSON. Errors use DRF's `{"detail": "..."}` shape (or a
per-field dict for validation errors) with status 400, 429 when throttled or
locked out, and 401/403 when unauthenticated.

| Method | Path | Body | Success |
|--------|------|------|---------|
| POST | `/auth/otp/generate/` | – | `{"secret": "...", "otpauth_url": "otpauth://totp/..."}` |
| POST | `/auth/otp/verify/` | `{"token": "123456"}` | `{"detail": "TOTP verified successfully"}` |
| GET | `/auth/otp/status/` | – | see below |
| POST | `/auth/otp/validate/` | `{"token": "123456"}` or a backup code | `{"detail": "Token is valid", "method": "totp"}` |
| POST | `/auth/otp/backup-codes/` | `{"token": "123456"}` (TOTP only) | `{"backup_codes": ["ABCDE-FGHJK", ...]}` |
| POST | `/auth/otp/disable/` | `{"token": "..."}`, optional `"password"` | `{"detail": "TOTP disabled successfully"}` |

`GET /auth/otp/status/`:

```json
{
  "otp_enabled": true,
  "otp_verified": true,
  "last_used_at": "2026-01-01T12:00:00Z",
  "backup_codes_remaining": 9,
  "created_at": "2026-01-01T11:58:00Z",
  "updated_at": "2026-01-01T12:00:00Z"
}
```

Notes:

- `/generate/` fails with 400 once TOTP is verified. Disable first to re-enroll.
- `/verify/` accepts only a TOTP code. `/validate/` and `/disable/` also accept
  a backup code (case and dashes are ignored). `/backup-codes/` accepts only a
  TOTP code, so a backup code cannot mint more backup codes.
- Each code is accepted once. Submitting the same code twice returns
  `Invalid token`.
- Before enrollment is complete, `/disable/` needs no token (there is no second
  factor to prove yet).
- `otp_enabled` always equals `otp_verified`; it is deprecated and will be
  removed in 0.3.

## Enforcing the second factor

drf-totp does not gate your views by itself. Two building blocks are provided.

### Session authentication

On a successful `/verify/` or `/validate/`, the current session is stamped.
`IsTOTPVerified` allows users who have no TOTP at all, and enrolled users whose
session carries a fresh stamp:

```python
from rest_framework.permissions import IsAuthenticated
from drf_totp.permissions import IsTOTPVerified

class SensitiveView(APIView):
    permission_classes = [IsAuthenticated, IsTOTPVerified]
```

The stamp records which user earned it and is ignored for any other user.
Set `TOTP_SESSION_MAX_AGE` (seconds) to require re-validation periodically.
Disabling TOTP clears the stamp. Use `IsTOTPEnrolled` to require that a user
has enabled TOTP at all.

### Token or JWT authentication

There is no session to stamp, so issue a limited credential after the password
step and a full one after `/validate/`. Typical shape:

1. Password login returns a short-lived "pre-auth" token whose only permitted
   endpoint is `/auth/otp/validate/`.
2. Connect to the `totp_validated` signal (or subclass `ValidateOTP`) and
   issue the real access token there.
3. Point `TOTP_VERIFIED_CHECK` at a callable that inspects the credential:

```python
# settings.py
TOTP_VERIFIED_CHECK = "myapp.auth.is_second_factor_verified"

# myapp/auth.py
def is_second_factor_verified(request) -> bool:
    return bool(getattr(request.auth, "payload", {}).get("mfa"))
```

`IsTOTPVerified` then uses your callable instead of the session stamp.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `TOTP_ISSUER_NAME` | `"drftotp"` | Issuer in the provisioning URI |
| `TOTP_ACCOUNT_LABEL` | `None` | Account label: `None` = email, then username; or a user attribute name; or a callable / dotted path taking the user |
| `TOTP_DIGITS` | `6` | Code length (6–8) |
| `TOTP_PERIOD` | `30` | Time step in seconds |
| `TOTP_VALID_WINDOW` | `1` | Steps accepted either side of now (clock drift) |
| `TOTP_THROTTLE_RATE` | `"5/min"` | Per-user rate for verify/validate/disable/backup-codes; `None` disables. `REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]["drf_totp"]` takes precedence |
| `TOTP_MAX_FAILED_ATTEMPTS` | `0` | Consecutive failures before a hard lockout; `0` disables |
| `TOTP_LOCKOUT_SECONDS` | `300` | Lockout duration |
| `TOTP_DISABLE_REQUIRES_PASSWORD` | `False` | Also require `password` on `/disable/` |
| `TOTP_SESSION_MAX_AGE` | `0` | Seconds a session stamp stays valid; `0` = for the session's lifetime |
| `TOTP_VERIFIED_CHECK` | `None` | Callable or dotted path `(request) -> bool` replacing the session check |
| `TOTP_ENCRYPTION_KEY` | `None` | Fernet key, or list of keys (newest first), encrypting secrets at rest |
| `TOTP_BACKUP_CODES_ENABLED` | `True` | Accept and issue backup codes |
| `TOTP_BACKUP_CODE_COUNT` | `10` | Codes issued per request |

Settings are read at request time, so they can be changed in tests with
`override_settings`.

Backup codes are stored as HMAC-SHA256 digests keyed with `SECRET_KEY`. When
you rotate `SECRET_KEY`, keep the old value in `SECRET_KEY_FALLBACKS` until
users have regenerated their codes, or the old codes stop working.

The drf-totp views opt out of `ATOMIC_REQUESTS`. A rejected code ends the
request with an error, and under `ATOMIC_REQUESTS` that would roll back the
failed-attempt counter and lockout.

Throttling uses Django's cache framework. The default local-memory cache works
for a single process; use a shared cache (Redis, Memcached) behind multiple
workers so the limit is enforced globally.

## Encryption at rest

```bash
pip install "drf-totp[encryption]"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

```python
TOTP_ENCRYPTION_KEY = env("TOTP_ENCRYPTION_KEY")
```

New secrets are stored as `fernet$...`. Existing plaintext rows stay readable;
re-encrypt them once:

```bash
python manage.py totp_reencrypt
```

To rotate, set `TOTP_ENCRYPTION_KEY = [new_key, old_key]`, run
`totp_reencrypt`, then drop the old key. `totp_reencrypt --decrypt` writes
plaintext back if you need to turn encryption off. `manage.py check` reports a
missing library or malformed key.

## Signals

All are sent with `sender=TOTPAuth`, `user=` and `request=` (may be `None`).

| Signal | Extra kwargs | When |
|--------|--------------|------|
| `drf_totp.signals.totp_enabled` | | enrollment confirmed |
| `drf_totp.signals.totp_disabled` | | TOTP disabled (API or admin action) |
| `drf_totp.signals.totp_validated` | `method` (`"totp"` / `"backup_code"`) | a code was accepted |
| `drf_totp.signals.totp_validation_failed` | `method` | a code was rejected |
| `drf_totp.signals.backup_codes_generated` | `count` | new backup codes issued |

Failed attempts and lockouts are also logged at WARNING level on the
`drf_totp` logger; secrets and submitted codes are never logged.

## Admin

`TOTPAuth` is registered read-only. The secret is not displayed. Two actions
are available: **Reset TOTP** (disables and deletes the secret and backup
codes) and **Clear lockout**.

## Client example

```javascript
const api = axios.create({ baseURL: "/auth/otp/" });

export const generateTotp = () => api.post("generate/").then(r => r.data);      // { secret, otpauth_url }
export const verifyTotp   = token => api.post("verify/", { token }).then(r => r.data);
export const getStatus    = () => api.get("status/").then(r => r.data);
export const validateTotp = token => api.post("validate/", { token }).then(r => r.data);
export const backupCodes  = token => api.post("backup-codes/", { token }).then(r => r.data.backup_codes);
export const disableTotp  = (token, password) => api.post("disable/", { token, password }).then(r => r.data);
```

Render `otpauth_url` as a QR code with any QR library; `secret` can be shown
for manual entry.

## Upgrading to 0.2

Run `python manage.py migrate`. Then review these behavior changes:

- `/status/` no longer returns `otp_auth_url`. Take the URI from `/generate/`.
- `/disable/` requires `{"token": ...}` for enrolled users.
- A code cannot be reused within its window.
- Token endpoints are rate limited (`5/min` per user by default).
- One step of clock drift is now tolerated.
- The `otp_auth_url` column is dropped by migration `0002_security_hardening`.
- `/verify/` returns 400 for a user who is already verified.
- `TOTPAuthSerializer` and `VerifyTOTPSerializer` still import but warn; switch
  to `TOTPStatusSerializer` and `TOTPTokenSerializer`.

See [CHANGELOG.md](CHANGELOG.md) for the complete list.

## Development

```bash
pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests
pytest --cov
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT License – see [LICENSE](LICENSE).
