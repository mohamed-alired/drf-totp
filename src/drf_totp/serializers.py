import warnings

from rest_framework import serializers

from . import conf
from .models import TOTPAuth


class TOTPStatusSerializer(serializers.ModelSerializer):
    backup_codes_remaining = serializers.IntegerField(read_only=True)

    class Meta:
        model = TOTPAuth
        fields = (
            "otp_enabled",
            "otp_verified",
            "last_used_at",
            "backup_codes_remaining",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


def empty_status():
    """Status payload for a user who never called ``/generate/``."""
    return {
        "otp_enabled": False,
        "otp_verified": False,
        "last_used_at": None,
        "backup_codes_remaining": 0,
        "created_at": None,
        "updated_at": None,
    }


class TOTPTokenSerializer(serializers.Serializer):
    """A TOTP code only (no backup codes)."""

    token = serializers.CharField(max_length=10)

    def validate_token(self, value):
        digits = conf.get_setting("TOTP_DIGITS")
        if not value.isascii() or not value.isdigit() or len(value) != digits:
            raise serializers.ValidationError(f"Token must be exactly {digits} digits.")
        return value


class CodeSerializer(serializers.Serializer):
    """A TOTP code or a backup code."""

    token = serializers.CharField(max_length=32)


class DisableSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=32, required=False, allow_blank=True)
    password = serializers.CharField(
        required=False, allow_blank=True, write_only=True, trim_whitespace=False
    )

    def validate(self, attrs):
        if conf.get_setting("TOTP_DISABLE_REQUIRES_PASSWORD"):
            user = self.context["request"].user
            password = attrs.get("password", "")
            if not password or not user.check_password(password):
                raise serializers.ValidationError({"password": "Invalid password."})
        return attrs


# Names from 0.1.x, kept importable until 0.3.
_DEPRECATED_ALIASES = {
    "TOTPAuthSerializer": "TOTPStatusSerializer",
    "VerifyTOTPSerializer": "TOTPTokenSerializer",
}


def __getattr__(name):
    if name in _DEPRECATED_ALIASES:
        new = _DEPRECATED_ALIASES[name]
        warnings.warn(
            f"drf_totp.serializers.{name} is deprecated and will be removed in 0.3; "
            f"use {new} instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return globals()[new]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
