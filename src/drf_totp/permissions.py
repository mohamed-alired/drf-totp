from rest_framework.permissions import BasePermission

from . import services


class IsTOTPVerified(BasePermission):
    """Allow users without TOTP, and users whose session validated a second factor.

    Combine with ``IsAuthenticated``. With session authentication the stamp is
    written by ``/verify/`` and ``/validate/``; for token or JWT setups point
    ``TOTP_VERIFIED_CHECK`` at your own ``callable(request) -> bool``.
    """

    message = "Second factor verification required."

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        auth = services.get_verified_auth(user)
        if auth is None:
            return True
        return services.is_session_verified(request, auth)


class IsTOTPEnrolled(BasePermission):
    """Allow only users who have completed TOTP enrollment."""

    message = "Two-factor authentication must be enabled."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and services.user_has_totp(user))
