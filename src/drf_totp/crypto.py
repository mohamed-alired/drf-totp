"""Optional encryption of TOTP secrets at rest.

When ``TOTP_ENCRYPTION_KEY`` is set (a Fernet key, or a list of keys with the
newest first to support rotation) secrets are stored as ``fernet$<token>``.
Values without the prefix are treated as plaintext so an existing deployment
can turn encryption on and re-encrypt with ``manage.py totp_reencrypt``.
"""

import functools

from django.core.exceptions import ImproperlyConfigured

from . import conf

PREFIX = "fernet$"


class CryptographyMissing(ImproperlyConfigured):
    """``TOTP_ENCRYPTION_KEY`` is set but the ``cryptography`` package is not installed."""


class InvalidEncryptionKey(ImproperlyConfigured):
    """``TOTP_ENCRYPTION_KEY`` contains a value that is not a valid Fernet key."""


def _keys():
    key = conf.get_setting("TOTP_ENCRYPTION_KEY")
    if not key:
        return None
    if isinstance(key, (str, bytes)):
        return [key]
    return list(key)


def get_fernet():
    """Return a ``MultiFernet`` for the configured key(s), or ``None`` when unset."""
    keys = _keys()
    if keys is None:
        return None
    return _build_fernet(tuple(keys))


@functools.lru_cache(maxsize=8)
def _build_fernet(keys):
    # Cached per key tuple: rebuilt only when the setting changes.
    try:
        from cryptography.fernet import Fernet, MultiFernet
    except ImportError as exc:
        raise CryptographyMissing(
            "TOTP_ENCRYPTION_KEY is set but 'cryptography' is not installed. "
            "Install it with: pip install 'drf-totp[encryption]'"
        ) from exc
    try:
        return MultiFernet([Fernet(k) for k in keys])
    except (ValueError, TypeError) as exc:
        raise InvalidEncryptionKey(
            "TOTP_ENCRYPTION_KEY must be a 32-byte url-safe base64 Fernet key. "
            "Generate one with: python -c 'from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())'"
        ) from exc


def is_encrypted(value):
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt(value):
    """Encrypt ``value`` if a key is configured, else return it unchanged."""
    if value is None or is_encrypted(value):
        return value
    fernet = get_fernet()
    if fernet is None:
        return value
    return PREFIX + fernet.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(value):
    """Decrypt ``value`` if it carries the prefix, else return it unchanged."""
    if not is_encrypted(value):
        return value
    fernet = get_fernet()
    if fernet is None:
        raise ImproperlyConfigured(
            "A TOTP secret is stored encrypted but TOTP_ENCRYPTION_KEY is not set."
        )
    from cryptography.fernet import InvalidToken

    try:
        return fernet.decrypt(value[len(PREFIX) :].encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ImproperlyConfigured(
            "A TOTP secret could not be decrypted with the configured TOTP_ENCRYPTION_KEY. "
            "If you rotated keys, keep the old key in the list."
        ) from exc
