import pytest
from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection

from drf_totp import crypto
from drf_totp.models import TOTPAuth

pytestmark = pytest.mark.django_db

KEY1 = Fernet.generate_key().decode()
KEY2 = Fernet.generate_key().decode()


def raw_secret(pk):
    with connection.cursor() as cur:
        cur.execute("SELECT otp_base32 FROM drf_totp_totpauth WHERE id = %s", [pk])
        return cur.fetchone()[0]


class TestEncryptedField:
    def test_plaintext_without_key(self, generated):
        assert raw_secret(generated.pk) == generated.otp_base32

    def test_encrypted_with_key(self, client, user, urls, frozen, settings, code):
        settings.TOTP_ENCRYPTION_KEY = KEY1
        secret = client.post(urls.generate).data["secret"]
        auth = TOTPAuth.objects.get(user=user)
        stored = raw_secret(auth.pk)
        assert stored.startswith("fernet$")
        assert secret not in stored
        assert auth.otp_base32 == secret
        # Full flow still works.
        assert client.post(urls.verify, {"token": code(auth)}).status_code == 200
        assert client.post(urls.validate, {"token": code(auth, 1)}).status_code == 200

    def test_key_rotation(self, generated, settings):
        settings.TOTP_ENCRYPTION_KEY = KEY1
        generated.save()
        assert raw_secret(generated.pk).startswith("fernet$")
        settings.TOTP_ENCRYPTION_KEY = [KEY2, KEY1]
        assert TOTPAuth.objects.get(pk=generated.pk).otp_base32 == generated.otp_base32
        settings.TOTP_ENCRYPTION_KEY = KEY2
        with pytest.raises(ImproperlyConfigured, match="could not be decrypted"):
            TOTPAuth.objects.get(pk=generated.pk)

    def test_encrypted_value_without_key_raises(self, generated, settings):
        settings.TOTP_ENCRYPTION_KEY = KEY1
        generated.save()
        settings.TOTP_ENCRYPTION_KEY = None
        with pytest.raises(ImproperlyConfigured, match="TOTP_ENCRYPTION_KEY is not set"):
            TOTPAuth.objects.get(pk=generated.pk)

    def test_legacy_plaintext_readable_with_key(self, generated, settings):
        plain = raw_secret(generated.pk)
        settings.TOTP_ENCRYPTION_KEY = KEY1
        assert TOTPAuth.objects.get(pk=generated.pk).otp_base32 == plain

    def test_invalid_key(self, settings):
        settings.TOTP_ENCRYPTION_KEY = "not-a-key"
        with pytest.raises(ImproperlyConfigured, match="Fernet key"):
            crypto.encrypt("x")

    def test_none_passthrough(self, settings):
        settings.TOTP_ENCRYPTION_KEY = KEY1
        assert crypto.encrypt(None) is None
        assert crypto.decrypt(None) is None


class TestReencryptCommand:
    def test_requires_key(self):
        with pytest.raises(CommandError):
            call_command("totp_reencrypt")

    def test_encrypt_then_decrypt(self, generated, settings, capsys):
        secret = generated.otp_base32
        settings.TOTP_ENCRYPTION_KEY = KEY1
        call_command("totp_reencrypt")
        assert raw_secret(generated.pk).startswith("fernet$")
        assert "Re-encrypted 1 secret(s)" in capsys.readouterr().out
        assert TOTPAuth.objects.get(pk=generated.pk).otp_base32 == secret

        call_command("totp_reencrypt", "--decrypt")
        assert raw_secret(generated.pk) == secret
        assert "Decrypted 1 secret(s)" in capsys.readouterr().out
        settings.TOTP_ENCRYPTION_KEY = None
        assert TOTPAuth.objects.get(pk=generated.pk).otp_base32 == secret


class TestChecks:
    def run(self):
        from django.core.checks import run_checks

        return [c.id for c in run_checks()]

    def test_clean_by_default(self):
        assert self.run() == []

    def test_bad_key(self, settings):
        settings.TOTP_ENCRYPTION_KEY = "bad"
        assert "drf_totp.E002" in self.run()

    def test_good_key(self, settings):
        settings.TOTP_ENCRYPTION_KEY = [KEY1, KEY2]
        assert self.run() == []

    def test_throttle_disabled_warns(self, settings):
        settings.TOTP_THROTTLE_RATE = None
        assert "drf_totp.W001" in self.run()

    @pytest.mark.parametrize("rate", ["five", "5/fortnight", "5", 5])
    def test_bad_rate(self, settings, rate):
        settings.TOTP_THROTTLE_RATE = rate
        assert "drf_totp.E003" in self.run()

    def test_bad_digits(self, settings):
        settings.TOTP_DIGITS = 4
        assert "drf_totp.E004" in self.run()


class TestFernetCache:
    def test_reused_until_key_changes(self, settings):
        settings.TOTP_ENCRYPTION_KEY = KEY1
        first = crypto.get_fernet()
        assert crypto.get_fernet() is first
        settings.TOTP_ENCRYPTION_KEY = [KEY2, KEY1]
        rotated = crypto.get_fernet()
        assert rotated is not first
        assert crypto.decrypt(crypto.encrypt("abc")) == "abc"

    def test_errors_are_typed_and_not_cached(self, settings):
        settings.TOTP_ENCRYPTION_KEY = "not-a-key"
        with pytest.raises(crypto.InvalidEncryptionKey):
            crypto.get_fernet()
        with pytest.raises(crypto.InvalidEncryptionKey):
            crypto.get_fernet()


class TestMissingCryptography:
    def test_check_reports_missing_library(self, settings, monkeypatch):
        import sys

        from django.core.checks import run_checks

        crypto._build_fernet.cache_clear()
        monkeypatch.setitem(sys.modules, "cryptography.fernet", None)
        settings.TOTP_ENCRYPTION_KEY = KEY1
        try:
            assert "drf_totp.E001" in [c.id for c in run_checks()]
            with pytest.raises(crypto.CryptographyMissing):
                crypto.get_fernet()
        finally:
            crypto._build_fernet.cache_clear()
