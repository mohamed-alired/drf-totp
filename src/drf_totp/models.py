from django.conf import settings
from django.db import models
from django.utils import timezone

from .fields import EncryptedCharField


class TOTPAuth(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="totp_auth"
    )
    # ``otp_enabled`` mirrors ``otp_verified`` and is kept for API compatibility.
    # It is deprecated and will be removed in 0.3.
    otp_enabled = models.BooleanField(default=False)
    otp_verified = models.BooleanField(default=False)
    otp_base32 = EncryptedCharField(max_length=255, null=True, blank=True)
    # Replay protection: the RFC 6238 time step of the last accepted token.
    last_used_step = models.BigIntegerField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    # Consecutive failures and optional hard lockout.
    failed_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "TOTP Authentication"
        verbose_name_plural = "TOTP Authentications"

    def __str__(self):
        return str(self.user)

    @property
    def is_locked(self):
        return bool(self.locked_until and self.locked_until > timezone.now())

    @property
    def backup_codes_remaining(self):
        return self.backup_codes.filter(used_at__isnull=True).count()


class TOTPBackupCode(models.Model):
    """A single-use recovery code. Only a salted hash is stored."""

    auth = models.ForeignKey(TOTPAuth, on_delete=models.CASCADE, related_name="backup_codes")
    code_hash = models.CharField(max_length=128)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "TOTP Backup Code"
        verbose_name_plural = "TOTP Backup Codes"

    def __str__(self):
        state = "used" if self.used_at else "unused"
        return f"Backup code for {self.auth.user} ({state})"
