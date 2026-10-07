from django.db import connections, transaction
from rest_framework import views
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from . import conf, services
from .exceptions import TokenRequired, TOTPNotEnabled, TOTPNotFound
from .models import TOTPAuth
from .serializers import (
    CodeSerializer,
    DisableSerializer,
    TOTPStatusSerializer,
    TOTPTokenSerializer,
    empty_status,
)
from .throttling import TOTPThrottle


def _get_auth(user, not_found_detail=None):
    auth = TOTPAuth.objects.filter(user=user).first()
    if auth is None:
        raise TOTPNotFound(not_found_detail)
    return auth


class TOTPAPIView(views.APIView):
    """Base view for drf-totp endpoints.

    The views are excluded from ``ATOMIC_REQUESTS``. A rejected code is
    reported by raising an exception, and under ``ATOMIC_REQUESTS`` DRF would
    then roll back the whole request, erasing the failed-attempt counter and
    lockout. The service layer opens its own transactions where it needs them.
    """

    permission_classes = [IsAuthenticated]

    @classmethod
    def as_view(cls, **initkwargs):
        view = super().as_view(**initkwargs)
        for alias in connections:
            view = transaction.non_atomic_requests(using=alias)(view)
        return view


class GenerateOTP(TOTPAPIView):
    """Generate (or regenerate) an unverified TOTP secret for the current user.

    Returns the base32 secret and the ``otpauth://`` provisioning URI. This is
    the only place the secret is ever returned. Fails once TOTP is verified;
    call ``/disable/`` first to re-enroll.
    """

    def post(self, request):
        _, secret, uri = services.setup_totp(request.user)
        return Response({"secret": secret, "otpauth_url": uri})


class VerifyOTP(TOTPAPIView):
    """Confirm enrollment with the first code from the authenticator app."""

    throttle_classes = [TOTPThrottle]

    def post(self, request):
        serializer = TOTPTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        auth = _get_auth(request.user)
        services.confirm_totp(auth, serializer.validated_data["token"], request)
        return Response({"detail": "TOTP verified successfully"})


class OTPStatus(TOTPAPIView):
    """Report TOTP state for the current user. Never includes the secret."""

    def get(self, request):
        auth = TOTPAuth.objects.filter(user=request.user).first()
        if auth is None:
            return Response(empty_status())
        return Response(TOTPStatusSerializer(auth).data)


class DisableOTP(TOTPAPIView):
    """Disable TOTP. Requires a valid TOTP or backup code once enrollment is complete.

    Set ``TOTP_DISABLE_REQUIRES_PASSWORD = True`` to also require the password.
    """

    throttle_classes = [TOTPThrottle]

    def post(self, request):
        serializer = DisableSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        auth = _get_auth(request.user, "TOTP auth not found")
        if auth.otp_verified:
            token = serializer.validated_data.get("token", "")
            if not token:
                raise TokenRequired("A valid token is required to disable TOTP.")
            services.validate_token(auth, token, request)
        services.disable_totp(auth, request)
        return Response({"detail": "TOTP disabled successfully"})


class ValidateOTP(TOTPAPIView):
    """Validate a TOTP code (or a backup code) for an enrolled user."""

    throttle_classes = [TOTPThrottle]

    def post(self, request):
        serializer = CodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        auth = _get_auth(request.user, "TOTP auth not found")
        method = services.validate_token(auth, serializer.validated_data["token"], request)
        return Response({"detail": "Token is valid", "method": method})


class BackupCodes(TOTPAPIView):
    """Issue a fresh set of backup codes. Requires a valid TOTP code (not a backup code)."""

    throttle_classes = [TOTPThrottle]

    def post(self, request):
        if not conf.get_setting("TOTP_BACKUP_CODES_ENABLED"):
            raise TOTPNotEnabled("Backup codes are disabled.")
        serializer = TOTPTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        auth = _get_auth(request.user, "TOTP auth not found")
        services.validate_token(
            auth, serializer.validated_data["token"], request, allow_backup=False
        )
        codes = services.generate_backup_codes(auth, request)
        return Response({"backup_codes": codes})
