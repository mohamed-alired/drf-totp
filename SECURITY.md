# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Email the maintainer at
solutiond700@gmail.com with a description, reproduction steps and the affected
version. You will get an acknowledgement within a few days and a fix or
mitigation plan as soon as possible. Credit is given in the changelog unless you
prefer otherwise.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | yes       |
| < 0.2   | no, upgrade: earlier versions expose the TOTP secret via `/otp/status/` |

## Threat model and guarantees

drf-totp implements the *second factor* only. What it guarantees:

- The secret is returned exactly once, from `/otp/generate/`, and never again.
- A code is accepted at most once (replay protection) and only within
  `TOTP_VALID_WINDOW` time steps of the server clock.
- Token endpoints are rate limited per user, with an optional hard lockout.
- Disabling TOTP requires proving possession of the second factor (or a backup
  code), optionally plus the password.
- Backup codes are stored only as HMAC-SHA256 digests keyed with
  `SECRET_KEY`; guessing them offline also requires the server key.
- The session stamp used by `IsTOTPVerified` is bound to the user who earned
  it and to the enrollment (secret) it was earned with.
- Failed-attempt counters persist under `ATOMIC_REQUESTS`.
- Secrets can be encrypted at rest with `TOTP_ENCRYPTION_KEY`.

What it does **not** do, and what your project must handle:

- **Enforcement.** Every endpoint requires an already-authenticated user.
  Nothing blocks a user from reaching your views before validating a code.
  Use `IsTOTPVerified` (session auth) or `TOTP_VERIFIED_CHECK` (token/JWT
  auth) on the views that must be protected. See the README.
- **Transport security.** Serve over HTTPS; the secret and codes travel in
  request/response bodies.
- **Database security.** Without `TOTP_ENCRYPTION_KEY`, secrets are stored in
  plaintext. Anyone with database read access can clone a user's
  authenticator.
- **Session security.** The session stamp inherits the lifetime and
  protections of Django's session framework.
- **Server clock.** TOTP depends on an accurate clock. Run NTP.
