from django.apps import AppConfig


class DrfTotpConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "drf_totp"
    verbose_name = "DRF TOTP Authentication"

    def ready(self):
        from . import checks  # noqa: F401  (registers system checks)
