import pytest
from django.contrib.auth import get_user_model

from drf_totp import services
from drf_totp.exceptions import (
    InvalidToken,
    TOTPAlreadyEnabled,
    TOTPNotEnabled,
    TOTPNotGenerated,
)
from drf_totp.models import TOTPAuth

pytestmark = pytest.mark.django_db


def upper_label(user):
    return user.get_username().upper()


class TestAccountLabel:
    def test_default_email(self, user):
        assert services.get_account_label(user) == "alice@example.com"

    def test_default_falls_back_to_username(self, user):
        user.email = None
        assert services.get_account_label(user) == "alice"

    def test_attribute_name(self, user, settings):
        settings.TOTP_ACCOUNT_LABEL = "first_name"
        user.first_name = "Alice"
        assert services.get_account_label(user) == "Alice"
        user.first_name = ""
        assert services.get_account_label(user) == "alice"

    def test_callable(self, user, settings):
        settings.TOTP_ACCOUNT_LABEL = upper_label
        assert services.get_account_label(user) == "ALICE"

    def test_dotted_path(self, user, settings):
        settings.TOTP_ACCOUNT_LABEL = "tests.test_services.upper_label"
        assert services.get_account_label(user) == "ALICE"

    def test_user_model_without_email_attribute(self, settings):
        class Stub:
            def get_username(self):
                return "stub"

        assert services.get_account_label(Stub()) == "stub"


class TestHelpers:
    def test_is_totp_format(self, settings):
        assert services.is_totp_format("123456")
        assert not services.is_totp_format("12345")
        assert not services.is_totp_format("abcdef")
        assert not services.is_totp_format(None)
        settings.TOTP_DIGITS = 8
        assert services.is_totp_format("12345678")

    def test_normalize_backup_code(self):
        assert services.normalize_backup_code(" ab2c3-d4e5f ") == "AB2C3D4E5F"

    def test_build_totp_uses_settings(self, settings):
        settings.TOTP_DIGITS = 7
        settings.TOTP_PERIOD = 60
        totp = services.build_totp("JBSWY3DPEHPK3PXP")
        assert totp.digits == 7 and totp.interval == 60

    def test_provisioning_uri_carries_period_and_digits(self, user, settings):
        settings.TOTP_DIGITS = 8
        settings.TOTP_PERIOD = 60
        uri = services.get_provisioning_uri("JBSWY3DPEHPK3PXP", user)
        assert "digits=8" in uri and "period=60" in uri


class TestServiceGuards:
    def test_setup_resets_state(self, user, frozen):
        auth, secret, uri = services.setup_totp(user)
        auth.failed_attempts = 3
        auth.last_used_step = 5
        auth.save()
        auth2, secret2, _ = services.setup_totp(user)
        assert auth2.pk == auth.pk
        assert secret2 != secret
        assert auth2.failed_attempts == 0 and auth2.last_used_step is None

    def test_setup_rejects_verified(self, enrolled, user):
        with pytest.raises(TOTPAlreadyEnabled):
            services.setup_totp(user)

    def test_verify_without_secret(self, user):
        auth = TOTPAuth.objects.create(user=user)
        with pytest.raises(TOTPNotGenerated):
            services.verify_totp_token(auth, "123456")
        with pytest.raises(TOTPNotGenerated):
            services.confirm_totp(auth, "123456")

    def test_validate_guards(self, generated, code):
        with pytest.raises(TOTPNotEnabled):
            services.validate_token(generated, code(generated))
        generated.otp_verified = generated.otp_enabled = True
        generated.save()
        with pytest.raises(InvalidToken):
            services.validate_token(generated, "000000")
        assert services.validate_token(generated, code(generated)) == "totp"

    def test_use_backup_code_rejects_bad_format(self, enrolled):
        assert services.use_backup_code(enrolled, "short") is False

    def test_user_has_totp(self, user, enrolled):
        assert services.user_has_totp(user) is True
        assert services.user_has_totp(get_user_model()()) is False
        from django.contrib.auth.models import AnonymousUser

        assert services.user_has_totp(AnonymousUser()) is False

    def test_model_str(self, enrolled, user):
        assert str(enrolled) == "alice"
        services.generate_backup_codes(enrolled)
        assert "unused" in str(enrolled.backup_codes.first())
