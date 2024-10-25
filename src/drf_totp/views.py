# author @djv-mo
from rest_framework import status, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import TOTPAuthSerializer, VerifyTOTPSerializer
from .models import TOTPAuth
from django.conf import settings
import pyotp

TOTP_ISSUER_NAME = getattr(settings, "TOTP_ISSUER_NAME", "drftotp")


class GenerateOTP(views.APIView):
    """
    Generate a new TOTP secret for the authenticated user.
    
    If TOTP is already enabled and verified for the user, returns an error.
    Otherwise, generates a new TOTP secret and provisioning URI.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        auth, created = TOTPAuth.objects.get_or_create(user=request.user)

        if auth.otp_verified:
            return Response(
                {"detail": "TOTP already enabled and verified."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        totp = pyotp.random_base32()
        auth.otp_base32 = totp

        provisioning_uri = pyotp.totp.TOTP(totp).provisioning_uri(
            name=request.user.email, issuer_name=TOTP_ISSUER_NAME
        )
        auth.otp_auth_url = provisioning_uri
        auth.save()

        return Response({"secret": totp, "otpauth_url": provisioning_uri})


class VerifyOTP(views.APIView):
    """
    Verify a TOTP token for the authenticated user.
    
    Requires a generated TOTP secret. If verification is successful,
    enables TOTP authentication for the user.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = VerifyTOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            auth = TOTPAuth.objects.get(user=request.user)

            if not auth.otp_base32:
                return Response(
                    {"detail": "TOTP not generated. Please generate TOTP first."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            totp = pyotp.TOTP(auth.otp_base32)

            if totp.verify(serializer.validated_data["token"]):
                auth.otp_verified = True
                auth.otp_enabled = True
                auth.save()
                return Response({"detail": "TOTP verified successfully"})

            return Response(
                {"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
            )

        except TOTPAuth.DoesNotExist:
            return Response(
                {"detail": "TOTP auth not found. Please generate TOTP first."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response(
                {"detail": "An error occurred while verifying TOTP."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class OTPStatus(views.APIView):
    """
    Get the current TOTP status for the authenticated user.
    
    Returns whether TOTP is enabled, verified, and associated metadata.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        auth, created = TOTPAuth.objects.get_or_create(user=request.user)
        serializer = TOTPAuthSerializer(auth)
        return Response(serializer.data)


class DisableOTP(views.APIView):
    """
    Disable TOTP authentication for the authenticated user.
    
    Removes the TOTP secret and disables TOTP verification.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            auth = TOTPAuth.objects.get(user=request.user)
            auth.otp_enabled = False
            auth.otp_verified = False
            auth.otp_base32 = None
            auth.otp_auth_url = None
            auth.save()
            return Response({"detail": "TOTP disabled successfully"})
        except TOTPAuth.DoesNotExist:
            return Response(
                {"detail": "TOTP auth not found"}, status=status.HTTP_400_BAD_REQUEST
            )


class ValidateOTP(views.APIView):
    """
    Validate a TOTP token for the authenticated user.
    
    Used to verify a token without enabling/disabling TOTP.
    Requires TOTP to be already enabled and verified.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = VerifyTOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            auth = TOTPAuth.objects.get(user=request.user)
            if not auth.otp_enabled or not auth.otp_verified:
                return Response(
                    {"detail": "TOTP not enabled"}, status=status.HTTP_400_BAD_REQUEST
                )

            totp = pyotp.TOTP(auth.otp_base32)
            if totp.verify(serializer.validated_data["token"]):
                return Response({"detail": "Token is valid"})

            return Response(
                {"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
            )
        except TOTPAuth.DoesNotExist:
            return Response(
                {"detail": "TOTP auth not found"}, status=status.HTTP_400_BAD_REQUEST
            )
