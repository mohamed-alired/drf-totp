from django.core.checks import Error, Tags, Warning, register

from . import conf, crypto

KEY_HINT = (
    "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
)


@register(Tags.security)
def check_encryption_key(app_configs, **kwargs):
    try:
        crypto.get_fernet()
    except crypto.CryptographyMissing:
        return [
            Error(
                "TOTP_ENCRYPTION_KEY is set but 'cryptography' is not installed.",
                hint="pip install 'drf-totp[encryption]'",
                id="drf_totp.E001",
            )
        ]
    except crypto.InvalidEncryptionKey:
        return [
            Error(
                "TOTP_ENCRYPTION_KEY contains a value that is not a valid Fernet key.",
                hint=KEY_HINT,
                id="drf_totp.E002",
            )
        ]
    return []


@register(Tags.security)
def check_throttle_rate(app_configs, **kwargs):
    from .throttling import TOTPThrottle

    rate = TOTPThrottle.configured_rate()
    try:
        TOTPThrottle()  # parses the rate exactly as requests will
    except (ValueError, KeyError, IndexError, AttributeError, TypeError):
        return [
            Error(
                f"TOTP throttle rate {rate!r} is not a valid DRF rate.",
                hint="Use the form '<number>/<second|minute|hour|day>'.",
                id="drf_totp.E003",
            )
        ]
    if rate is None:
        return [
            Warning(
                "TOTP throttling is disabled; token endpoints can be brute-forced.",
                hint="Set TOTP_THROTTLE_RATE (e.g. '5/min').",
                id="drf_totp.W001",
            )
        ]
    return []


@register(Tags.security)
def check_digits(app_configs, **kwargs):
    digits = conf.get_setting("TOTP_DIGITS")
    if not isinstance(digits, int) or not 6 <= digits <= 8:
        return [
            Error(
                "TOTP_DIGITS must be an integer between 6 and 8.",
                id="drf_totp.E004",
            )
        ]
    return []
