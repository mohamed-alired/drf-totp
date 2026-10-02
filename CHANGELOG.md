# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-09-30

Security-focused release. See "Upgrading to 0.2" in the README.

### Security
- `/otp/status/` no longer returns `otp_auth_url`, which embedded the TOTP secret.
  The secret is now only ever returned by `/otp/generate/`.
- `/otp/disable/` requires a valid TOTP code or backup code once enrollment is
  complete. `TOTP_DISABLE_REQUIRES_PASSWORD` additionally requires the password.
- Replay protection: a time step that was already accepted is rejected
  (RFC 6238 §5.2), enforced under a database row lock.
- Per-user throttling on `/verify/`, `/validate/`, `/disable/` and
  `/backup-codes/` (`TOTP_THROTTLE_RATE`, default `5/min`).
- Optional hard lockout after consecutive failures (`TOTP_MAX_FAILED_ATTEMPTS`,
  `TOTP_LOCKOUT_SECONDS`).
- Optional encryption of secrets at rest with Fernet (`TOTP_ENCRYPTION_KEY`,
  install `drf-totp[encryption]`), with key rotation and a
  `totp_reencrypt` management command.
- The admin no longer displays or edits the secret; all fields are read-only
  and a "Reset TOTP" action replaces manual editing.
- Backup codes are stored as HMAC-SHA256 keyed with `SECRET_KEY`, so a
  database leak alone does not allow offline brute force. Keys listed in
  `SECRET_KEY_FALLBACKS` are honoured; rotating `SECRET_KEY` without a fallback
  invalidates existing backup codes.
- The session stamp used by `IsTOTPVerified` records the user it was issued
  for and is ignored for any other user (relevant when token auth and session
  cookies are used together).
- The drf-totp views are excluded from `ATOMIC_REQUESTS`, so failed-attempt
  counters and lockouts persist even though the request ends in an error.

### Added
- Backup (recovery) codes: `POST /otp/backup-codes/` issues a fresh set of
  hashed single-use codes; `/validate/` and `/disable/` accept them.
- `IsTOTPVerified` and `IsTOTPEnrolled` permission classes, a session stamp
  written on successful validation, `TOTP_SESSION_MAX_AGE` and a
  `TOTP_VERIFIED_CHECK` hook for token/JWT setups.
- Signals: `totp_enabled`, `totp_disabled`, `totp_validated`,
  `totp_validation_failed`, `backup_codes_generated`.
- Logging under the `drf_totp` logger.
- Settings: `TOTP_ACCOUNT_LABEL`, `TOTP_DIGITS`, `TOTP_PERIOD`,
  `TOTP_VALID_WINDOW`, `TOTP_BACKUP_CODES_ENABLED`, `TOTP_BACKUP_CODE_COUNT`.
- System checks for misconfigured keys, throttle rates and digit counts.
- `last_used_at` and `backup_codes_remaining` in the status response.
- `method` (`"totp"` or `"backup_code"`) in the validate response.

### Changed
- Clock drift of one time step either side is accepted by default
  (`TOTP_VALID_WINDOW = 1`).
- The account label falls back to `get_username()` when the user has no email
  (previously the label was the literal string `Secret`).
- All `TOTP_*` settings are read lazily, so `override_settings` works.
- `/otp/status/` no longer creates a row as a side effect of a GET.
- Internal errors are no longer swallowed into a generic 500.
- `/otp/verify/` for a user who is already verified returns 400
  (`TOTP already enabled and verified.`) instead of re-verifying.
- Enrollment is decided by `otp_verified` alone.
- Minimum Python is 3.9; Django 4.2, 5.1 and 5.2 are tested.

### Deprecated
- `otp_enabled` duplicates `otp_verified` and will be removed in 0.3.
- `drf_totp.serializers.TOTPAuthSerializer` and `VerifyTOTPSerializer` are
  aliases of `TOTPStatusSerializer` and `TOTPTokenSerializer` that emit a
  `DeprecationWarning`; they will be removed in 0.3.

### Removed
- Column `otp_auth_url` (migration `0002_security_hardening`).
- Module constant `drf_totp.views.TOTP_ISSUER_NAME`; read
  `drf_totp.conf.get_setting("TOTP_ISSUER_NAME")` instead.

## [0.1.5] - 2024-10-23
- Initial public releases (0.1.0 – 0.1.5).

[Unreleased]: https://github.com/mohamed-alired/drf-totp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mohamed-alired/drf-totp/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/mohamed-alired/drf-totp/releases/tag/v0.1.5
