from rest_framework import status
from rest_framework.exceptions import APIException


class TOTPError(APIException):
    """Base class for errors surfaced by drf-totp. Rendered as ``{"detail": ...}``."""

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "TOTP error."
    default_code = "totp_error"


class TOTPNotFound(TOTPError):
    default_detail = "TOTP auth not found. Please generate TOTP first."
    default_code = "totp_not_found"


class TOTPNotGenerated(TOTPError):
    default_detail = "TOTP not generated. Please generate TOTP first."
    default_code = "totp_not_generated"


class TOTPAlreadyEnabled(TOTPError):
    default_detail = "TOTP already enabled and verified."
    default_code = "totp_already_enabled"


class TOTPNotEnabled(TOTPError):
    default_detail = "TOTP not enabled"
    default_code = "totp_not_enabled"


class InvalidToken(TOTPError):
    default_detail = "Invalid token"
    default_code = "invalid_token"


class TokenRequired(TOTPError):
    default_detail = "A valid token is required."
    default_code = "token_required"


class TOTPLocked(TOTPError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = "Too many failed attempts. Try again later."
    default_code = "totp_locked"
