from django.core.checks import Error, Tags, Warning, register

from . import conf


@register(Tags.security)
def check_encryption_key(app_configs, **kwargs):
    errors = []
    key = conf.get_setting("TOTP_ENCRYPTION_KEY")
    if not key:
        return errors
    try:
        from cryptography.fernet import Fernet  # noqa: F401
    except ImportError:
        errors.append(
            Error(
                "TOTP_ENCRYPTION_KEY is set but 'cryptography' is not installed.",
                hint="pip install 'drf-totp[encryption]'",
                id="drf_totp.E001",
            )
        )
        return errors
    keys = [key] if isinstance(key, (str, bytes)) else list(key)
    for k in keys:
        try:
            Fernet(k)
        except (ValueError, TypeError):
            errors.append(
                Error(
                    "TOTP_ENCRYPTION_KEY contains a value that is not a valid Fernet key.",
                    hint="python -c 'from cryptography.fernet import Fernet; "
                    "print(Fernet.generate_key().decode())'",
                    id="drf_totp.E002",
                )
            )
            break
    return errors


@register(Tags.security)
def check_throttle_rate(app_configs, **kwargs):
    from rest_framework.settings import api_settings
    from rest_framework.throttling import SimpleRateThrottle

    rates = api_settings.DEFAULT_THROTTLE_RATES or {}
    rate = rates["drf_totp"] if "drf_totp" in rates else conf.get_setting("TOTP_THROTTLE_RATE")
    if rate is None:
        return [
            Warning(
                "TOTP throttling is disabled; token endpoints can be brute-forced.",
                hint="Set TOTP_THROTTLE_RATE (e.g. '5/min').",
                id="drf_totp.W001",
            )
        ]
    try:
        SimpleRateThrottle.parse_rate(None, rate)
    except (ValueError, KeyError, IndexError, AttributeError, TypeError):
        return [
            Error(
                f"TOTP throttle rate {rate!r} is not a valid DRF rate.",
                hint="Use the form '<number>/<second|minute|hour|day>'.",
                id="drf_totp.E003",
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
