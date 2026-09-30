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
        raise TOTPNotFound(not_found_detail) if not_found_detail else TOTPNotFound()
    return auth


class GenerateOTP(views.APIView):
    """Generate (or regenerate) an unverified TOTP secret for the current user.

    Returns the base32 secret and the ``otpauth://`` provisioning URI. This is
    the only place the secret is ever returned. Fails once TOTP is verified;
    call ``/disable/`` first to re-enroll.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        _, secret, uri = services.setup_totp(request.user)
        return Response({"secret": secret, "otpauth_url": uri})


class VerifyOTP(views.APIView):
    """Confirm enrollment with the first code from the authenticator app."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [TOTPThrottle]

    def post(self, request):
        serializer = TOTPTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        auth = _get_auth(request.user)
        services.confirm_totp(auth, serializer.validated_data["token"], request)
        return Response({"detail": "TOTP verified successfully"})


class OTPStatus(views.APIView):
    """Report TOTP state for the current user. Never includes the secret."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        auth = TOTPAuth.objects.filter(user=request.user).first()
        if auth is None:
            return Response(empty_status())
        return Response(TOTPStatusSerializer(auth).data)


class DisableOTP(views.APIView):
    """Disable TOTP. Requires a valid TOTP or backup code once enrollment is complete.

    Set ``TOTP_DISABLE_REQUIRES_PASSWORD = True`` to also require the password.
    """

    permission_classes = [IsAuthenticated]
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


class ValidateOTP(views.APIView):
    """Validate a TOTP code (or a backup code) for an enrolled user."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [TOTPThrottle]

    def post(self, request):
        serializer = CodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        auth = _get_auth(request.user, "TOTP auth not found")
        method = services.validate_token(auth, serializer.validated_data["token"], request)
        return Response({"detail": "Token is valid", "method": method})


class BackupCodes(views.APIView):
    """Issue a fresh set of backup codes. Requires a valid TOTP code (not a backup code)."""

    permission_classes = [IsAuthenticated]
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
