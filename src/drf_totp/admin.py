from django.contrib import admin, messages
from django.contrib.auth import get_user_model

from . import services
from .models import TOTPAuth, TOTPBackupCode


class TOTPBackupCodeInline(admin.TabularInline):
    model = TOTPBackupCode
    fields = ("created_at", "used_at")
    readonly_fields = fields
    extra = 0
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(TOTPAuth)
class TOTPAuthAdmin(admin.ModelAdmin):
    """Read-only view of TOTP state. The secret is never displayed or editable."""

    list_display = (
        "user",
        "otp_verified",
        "last_used_at",
        "failed_attempts",
        "locked_until",
        "updated_at",
    )
    list_filter = ("otp_verified",)
    search_fields = (f"user__{get_user_model().USERNAME_FIELD}",)
    fields = (
        "user",
        "otp_enabled",
        "otp_verified",
        "last_used_at",
        "last_used_step",
        "failed_attempts",
        "locked_until",
        "created_at",
        "updated_at",
    )
    readonly_fields = fields
    inlines = [TOTPBackupCodeInline]
    actions = ["reset_totp", "unlock"]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        # Deleting the row would disable 2FA without the log line and signal
        # that the audited "Reset TOTP" action produces.
        return False

    @admin.action(description="Reset TOTP (disable and delete secret and backup codes)")
    def reset_totp(self, request, queryset):
        for auth in queryset:
            services.disable_totp(auth, request)
        self.message_user(request, f"Reset TOTP for {queryset.count()} user(s).", messages.SUCCESS)

    @admin.action(description="Clear lockout and failed attempts")
    def unlock(self, request, queryset):
        updated = queryset.update(failed_attempts=0, locked_until=None)
        self.message_user(request, f"Unlocked {updated} user(s).", messages.SUCCESS)
