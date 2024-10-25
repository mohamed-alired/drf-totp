from rest_framework import serializers
from .models import TOTPAuth


class TOTPAuthSerializer(serializers.ModelSerializer):
    class Meta:
        model = TOTPAuth
        fields = ("otp_enabled", "otp_verified", "otp_auth_url")
        read_only_fields = fields


class VerifyTOTPSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=6, min_length=6)
