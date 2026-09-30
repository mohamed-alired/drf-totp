"""All TOTP business logic. Views are thin wrappers around these functions."""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import time
from datetime import timedelta

import pyotp
from django.db import transaction
from django.utils import timezone
from django.utils.module_loading import import_string
from pyotp.utils import strings_equal

from . import conf, signals
from .exceptions import (
    InvalidToken,
    TOTPAlreadyEnabled,
    TOTPLocked,
    TOTPNotEnabled,
    TOTPNotGenerated,
)
from .models import TOTPAuth, TOTPBackupCode

logger = logging.getLogger("drf_totp")

#: Session key holding the UNIX timestamp of the last successful validation.
SESSION_KEY = "drf_totp_verified_at"

# Backup codes use an unambiguous alphabet (no 0/O, 1/I).
BACKUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
BACKUP_CODE_LENGTH = 10
_BACKUP_CODE_RE = re.compile(r"^[A-Z2-9]{10}$")


# --------------------------------------------------------------------------- #
# Provisioning
# --------------------------------------------------------------------------- #
def get_account_label(user) -> str:
    """Return the account label shown in the authenticator app."""
    label_setting = conf.get_setting("TOTP_ACCOUNT_LABEL")
    if label_setting is None:
        value = getattr(user, "email", None) or user.get_username()
    elif callable(label_setting):
        value = label_setting(user)
    elif isinstance(label_setting, str) and "." in label_setting:
        value = import_string(label_setting)(user)
    else:
        value = getattr(user, label_setting)
    return str(value or user.get_username())


def build_totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(
        secret,
        digits=conf.get_setting("TOTP_DIGITS"),
        interval=conf.get_setting("TOTP_PERIOD"),
    )


def generate_secret() -> str:
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, user) -> str:
    return build_totp(secret).provisioning_uri(
        name=get_account_label(user), issuer_name=conf.get_setting("TOTP_ISSUER_NAME")
    )


def is_totp_format(token: str) -> bool:
    digits = conf.get_setting("TOTP_DIGITS")
    return bool(re.fullmatch(rf"\d{{{digits}}}", token or ""))


def setup_totp(user):
    """Create or reset an unverified TOTP secret for ``user``.

    Returns ``(auth, secret, provisioning_uri)``. Raises ``TOTPAlreadyEnabled``
    when the user already has a confirmed second factor.
    """
    auth, _ = TOTPAuth.objects.get_or_create(user=user)
    if auth.otp_verified:
        raise TOTPAlreadyEnabled()
    secret = generate_secret()
    auth.otp_base32 = secret
    auth.otp_enabled = False
    auth.otp_verified = False
    auth.last_used_step = None
    auth.failed_attempts = 0
    auth.locked_until = None
    auth.save()
    return auth, secret, get_provisioning_uri(secret, user)


def user_has_totp(user) -> bool:
    if not getattr(user, "is_authenticated", False) or getattr(user, "pk", None) is None:
        return False
    return TOTPAuth.objects.filter(user=user, otp_verified=True).exists()


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def _check_lock(auth: TOTPAuth, now):
    if auth.locked_until and auth.locked_until > now:
        logger.warning("TOTP locked for user id=%s until %s", auth.user_id, auth.locked_until)
        raise TOTPLocked()


def _record_failure(auth: TOTPAuth, now, method: str, request=None):
    auth.failed_attempts += 1
    max_failures = conf.get_setting("TOTP_MAX_FAILED_ATTEMPTS")
    update_fields = ["failed_attempts", "updated_at"]
    if max_failures and auth.failed_attempts >= max_failures:
        auth.locked_until = now + timedelta(seconds=conf.get_setting("TOTP_LOCKOUT_SECONDS"))
        auth.failed_attempts = 0
        update_fields.append("locked_until")
        logger.warning("TOTP lockout for user id=%s until %s", auth.user_id, auth.locked_until)
    auth.save(update_fields=update_fields)
    logger.warning("TOTP %s validation failed for user id=%s", method, auth.user_id)
    signals.totp_validation_failed.send(
        sender=TOTPAuth, user=auth.user, request=request, method=method
    )


def _record_success(auth: TOTPAuth, now, method: str, request=None, step=None):
    auth.failed_attempts = 0
    auth.locked_until = None
    auth.last_used_at = now
    update_fields = ["failed_attempts", "locked_until", "last_used_at", "updated_at"]
    if step is not None:
        auth.last_used_step = step
        update_fields.append("last_used_step")
    auth.save(update_fields=update_fields)
    logger.info("TOTP %s validated for user id=%s", method, auth.user_id)
    signals.totp_validated.send(sender=TOTPAuth, user=auth.user, request=request, method=method)


def _matching_step(totp: pyotp.TOTP, token: str, now):
    """Return the time step whose code equals ``token`` within the allowed window."""
    window = conf.get_setting("TOTP_VALID_WINDOW")
    current = totp.timecode(now)
    for offset in range(-window, window + 1):
        step = current + offset
        if strings_equal(totp.generate_otp(step), token):
            return step
    return None


def _copy_state(src: TOTPAuth, dst: TOTPAuth):
    for name in ("failed_attempts", "locked_until", "last_used_at", "last_used_step"):
        setattr(dst, name, getattr(src, name))


def verify_totp_token(auth: TOTPAuth, token: str, request=None) -> bool:
    """Check ``token`` against ``auth``'s secret with drift window and replay protection.

    Runs under a row lock so two concurrent requests cannot both consume the
    same time step. Raises ``TOTPLocked`` during a lockout and
    ``TOTPNotGenerated`` when no secret exists.
    """
    with transaction.atomic():
        locked = TOTPAuth.objects.select_for_update().get(pk=auth.pk)
        now = timezone.now()
        _check_lock(locked, now)
        if not locked.otp_base32:
            raise TOTPNotGenerated()
        step = _matching_step(build_totp(locked.otp_base32), token, now)
        replayed = (
            step is not None and locked.last_used_step is not None and step <= locked.last_used_step
        )
        if step is None or replayed:
            if replayed:
                logger.warning("TOTP replay rejected for user id=%s", auth.user_id)
            _record_failure(locked, now, "totp", request)
            _copy_state(locked, auth)
            return False
        _record_success(locked, now, "totp", request, step=step)
        _copy_state(locked, auth)
        return True


def confirm_totp(auth: TOTPAuth, token: str, request=None) -> None:
    """Complete enrollment: accept ``token`` and enable TOTP for the user."""
    if auth.otp_verified:
        raise TOTPAlreadyEnabled()
    if not auth.otp_base32:
        raise TOTPNotGenerated()
    if not verify_totp_token(auth, token, request):
        raise InvalidToken()
    auth.otp_verified = True
    auth.otp_enabled = True
    auth.save(update_fields=["otp_verified", "otp_enabled", "updated_at"])
    logger.info("TOTP enabled for user id=%s", auth.user_id)
    signals.totp_enabled.send(sender=TOTPAuth, user=auth.user, request=request)
    mark_session_verified(request)


def validate_token(auth: TOTPAuth, token: str, request=None, allow_backup: bool = True) -> str:
    """Validate a TOTP code or, when allowed, a backup code.

    Returns ``"totp"`` or ``"backup_code"``. Raises ``TOTPNotEnabled`` when the
    user has not completed enrollment and ``InvalidToken`` on rejection.
    """
    if not auth.otp_verified or not auth.otp_enabled:
        raise TOTPNotEnabled()
    token = (token or "").strip()
    if is_totp_format(token):
        if verify_totp_token(auth, token, request):
            mark_session_verified(request)
            return "totp"
        raise InvalidToken()
    backup_allowed = allow_backup and conf.get_setting("TOTP_BACKUP_CODES_ENABLED")
    if backup_allowed and use_backup_code(auth, token, request):
        mark_session_verified(request)
        return "backup_code"
    raise InvalidToken()


def disable_totp(auth: TOTPAuth, request=None) -> None:
    """Remove the secret and every backup code; TOTP is no longer required."""
    auth.otp_enabled = False
    auth.otp_verified = False
    auth.otp_base32 = None
    auth.last_used_step = None
    auth.last_used_at = None
    auth.failed_attempts = 0
    auth.locked_until = None
    auth.save()
    auth.backup_codes.all().delete()
    logger.info("TOTP disabled for user id=%s", auth.user_id)
    signals.totp_disabled.send(sender=TOTPAuth, user=auth.user, request=request)
    clear_session_verified(request)


# --------------------------------------------------------------------------- #
# Backup codes
# --------------------------------------------------------------------------- #
def normalize_backup_code(code: str) -> str:
    return re.sub(r"[\s\-]", "", (code or "")).upper()


def format_backup_code(code: str) -> str:
    half = BACKUP_CODE_LENGTH // 2
    return f"{code[:half]}-{code[half:]}"


def _hash_backup_code(code: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{code}".encode()).hexdigest()


def _make_code_hash(code: str) -> str:
    salt = secrets.token_hex(8)
    return f"{salt}${_hash_backup_code(code, salt)}"


def _check_code_hash(code: str, stored: str) -> bool:
    salt, _, digest = stored.partition("$")
    return hmac.compare_digest(_hash_backup_code(code, salt), digest)


def generate_backup_codes(auth: TOTPAuth, request=None) -> list[str]:
    """Replace all backup codes with a fresh set and return them in plain text (once)."""
    count = conf.get_setting("TOTP_BACKUP_CODE_COUNT")
    codes = [
        "".join(secrets.choice(BACKUP_ALPHABET) for _ in range(BACKUP_CODE_LENGTH))
        for _ in range(count)
    ]
    with transaction.atomic():
        auth.backup_codes.all().delete()
        TOTPBackupCode.objects.bulk_create(
            [TOTPBackupCode(auth=auth, code_hash=_make_code_hash(c)) for c in codes]
        )
    logger.info("Backup codes generated for user id=%s (count=%s)", auth.user_id, count)
    signals.backup_codes_generated.send(
        sender=TOTPAuth, user=auth.user, request=request, count=count
    )
    return [format_backup_code(c) for c in codes]


def use_backup_code(auth: TOTPAuth, code: str, request=None) -> bool:
    """Consume ``code`` if it is an unused backup code. Subject to lockout rules."""
    code = normalize_backup_code(code)
    if not _BACKUP_CODE_RE.match(code):
        return False
    with transaction.atomic():
        locked = TOTPAuth.objects.select_for_update().get(pk=auth.pk)
        now = timezone.now()
        _check_lock(locked, now)
        for backup in locked.backup_codes.select_for_update().filter(used_at__isnull=True):
            if _check_code_hash(code, backup.code_hash):
                backup.used_at = now
                backup.save(update_fields=["used_at"])
                _record_success(locked, now, "backup_code", request)
                _copy_state(locked, auth)
                return True
        _record_failure(locked, now, "backup_code", request)
        _copy_state(locked, auth)
        return False


# --------------------------------------------------------------------------- #
# Session helpers (used by ``IsTOTPVerified``)
# --------------------------------------------------------------------------- #
def _session(request):
    return getattr(request, "session", None) if request is not None else None


def mark_session_verified(request) -> None:
    session = _session(request)
    if session is not None:
        session[SESSION_KEY] = int(time.time())


def clear_session_verified(request) -> None:
    session = _session(request)
    if session is not None:
        session.pop(SESSION_KEY, None)


def is_session_verified(request) -> bool:
    """True when the current session validated a second factor recently enough."""
    check = conf.get_setting("TOTP_VERIFIED_CHECK")
    if check:
        if isinstance(check, str):
            check = import_string(check)
        return bool(check(request))
    session = _session(request)
    if session is None:
        return False
    stamp = session.get(SESSION_KEY)
    if not stamp:
        return False
    max_age = conf.get_setting("TOTP_SESSION_MAX_AGE")
    expired = bool(max_age) and time.time() - stamp > max_age
    return not expired
