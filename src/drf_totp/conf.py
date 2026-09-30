"""Lazy access to ``TOTP_*`` settings.

Every setting is read from ``django.conf.settings`` at call time, so
``override_settings`` works and nothing is frozen at import.
"""

from django.conf import settings

DEFAULTS = {
    # Issuer shown in authenticator apps and embedded in the provisioning URI.
    "TOTP_ISSUER_NAME": "drftotp",
    # Account label in the provisioning URI. ``None`` uses the user's email,
    # falling back to ``get_username()``. May also be a user attribute name,
    # a callable, or a dotted path to a callable taking the user.
    "TOTP_ACCOUNT_LABEL": None,
    # Code length and time step, in the RFC 6238 sense.
    "TOTP_DIGITS": 6,
    "TOTP_PERIOD": 30,
    # Number of time steps accepted either side of "now" (clock drift).
    "TOTP_VALID_WINDOW": 1,
    # DRF throttle rate for verify/validate/disable/backup-codes. ``None`` disables.
    "TOTP_THROTTLE_RATE": "5/min",
    # Hard lockout after this many consecutive failures. 0 disables.
    "TOTP_MAX_FAILED_ATTEMPTS": 0,
    "TOTP_LOCKOUT_SECONDS": 300,
    # Also require the account password to disable TOTP.
    "TOTP_DISABLE_REQUIRES_PASSWORD": False,
    # Freshness (seconds) of the session stamp used by ``IsTOTPVerified``. 0 = never expires.
    "TOTP_SESSION_MAX_AGE": 0,
    # Dotted path to ``callable(request) -> bool`` replacing the session check.
    "TOTP_VERIFIED_CHECK": None,
    # Fernet key (or list of keys, newest first) encrypting secrets at rest.
    "TOTP_ENCRYPTION_KEY": None,
    # Backup (recovery) codes.
    "TOTP_BACKUP_CODES_ENABLED": True,
    "TOTP_BACKUP_CODE_COUNT": 10,
}


def get_setting(name):
    """Return the value of ``name`` from settings, or its documented default."""
    return getattr(settings, name, DEFAULTS[name])
