import json

import pytest
from rest_framework import status

from drf_totp.models import TOTPAuth, TOTPBackupCode

pytestmark = pytest.mark.django_db


class TestGenerate:
    def test_returns_secret_and_uri(self, client, user, urls, frozen):
        resp = client.post(urls.generate)
        assert resp.status_code == 200
        assert set(resp.data) == {"secret", "otpauth_url"}
        assert resp.data["otpauth_url"].startswith("otpauth://totp/drftotp:alice%40example.com?")
        assert f"secret={resp.data['secret']}" in resp.data["otpauth_url"]
        assert "issuer=drftotp" in resp.data["otpauth_url"]
        auth = TOTPAuth.objects.get(user=user)
        assert auth.otp_base32 == resp.data["secret"]
        assert auth.otp_verified is False

    def test_regenerate_rotates_unverified_secret(self, client, urls, frozen, user):
        first = client.post(urls.generate).data["secret"]
        second = client.post(urls.generate).data["secret"]
        assert first != second
        assert TOTPAuth.objects.get(user=user).otp_base32 == second

    def test_rejected_once_verified(self, client, enrolled, urls):
        resp = client.post(urls.generate)
        assert resp.status_code == 400
        assert resp.data["detail"] == "TOTP already enabled and verified."

    def test_issuer_setting_is_read_lazily(self, client, urls, frozen, settings):
        settings.TOTP_ISSUER_NAME = "Acme Corp"
        resp = client.post(urls.generate)
        assert resp.data["otpauth_url"].startswith("otpauth://totp/Acme%20Corp:")
        assert "issuer=Acme%20Corp" in resp.data["otpauth_url"]

    def test_label_falls_back_to_username(self, client, user, urls, frozen):
        user.email = ""
        user.save()
        resp = client.post(urls.generate)
        assert "otpauth://totp/drftotp:alice?" in resp.data["otpauth_url"]


class TestVerify:
    def test_requires_generate_first(self, client, urls):
        resp = client.post(urls.verify, {"token": "123456"})
        assert resp.status_code == 400
        assert resp.data["detail"] == "TOTP auth not found. Please generate TOTP first."

    @pytest.mark.parametrize("token", ["12345", "1234567", "abcdef", "", "12 456", "１２３４５６"])
    def test_rejects_malformed_tokens(self, client, generated, urls, token):
        resp = client.post(urls.verify, {"token": token})
        assert resp.status_code == 400
        assert "token" in resp.data

    def test_valid_code_enables(self, client, generated, urls, code, user):
        resp = client.post(urls.verify, {"token": code(generated)})
        assert resp.status_code == 200
        assert resp.data == {"detail": "TOTP verified successfully"}
        auth = TOTPAuth.objects.get(user=user)
        assert auth.otp_verified and auth.otp_enabled
        assert auth.last_used_step is not None
        assert auth.last_used_at is not None

    def test_invalid_code(self, client, generated, urls):
        resp = client.post(urls.verify, {"token": "000000"})
        assert resp.status_code == 400
        assert resp.data["detail"] == "Invalid token"
        assert TOTPAuth.objects.get(pk=generated.pk).otp_verified is False

    def test_already_verified(self, client, enrolled, urls, code):
        resp = client.post(urls.verify, {"token": code(enrolled)})
        assert resp.status_code == 400
        assert resp.data["detail"] == "TOTP already enabled and verified."

    def test_missing_secret(self, client, generated, urls):
        TOTPAuth.objects.filter(pk=generated.pk).update(otp_base32=None)
        resp = client.post(urls.verify, {"token": "123456"})
        assert resp.status_code == 400
        assert resp.data["detail"] == "TOTP not generated. Please generate TOTP first."


class TestStatus:
    def test_empty_without_side_effects(self, client, user, urls):
        resp = client.get(urls.status)
        assert resp.status_code == 200
        assert resp.data == {
            "otp_enabled": False,
            "otp_verified": False,
            "last_used_at": None,
            "backup_codes_remaining": 0,
            "created_at": None,
            "updated_at": None,
        }
        assert not TOTPAuth.objects.filter(user=user).exists()

    def test_never_exposes_secret(self, client, generated, urls):
        resp = client.get(urls.status)
        body = json.dumps(resp.data, default=str)
        assert "otp_auth_url" not in resp.data
        assert "secret" not in body
        assert generated.otp_base32 not in body
        assert resp.data["otp_verified"] is False

    def test_after_enrollment(self, client, enrolled, urls):
        resp = client.get(urls.status)
        assert resp.data["otp_enabled"] is True
        assert resp.data["otp_verified"] is True
        assert resp.data["last_used_at"] is not None
        assert resp.data["backup_codes_remaining"] == 0

    def test_post_not_allowed(self, client, urls):
        assert client.post(urls.status).status_code == 405


class TestDisable:
    def test_not_found(self, client, urls):
        resp = client.post(urls.disable)
        assert resp.status_code == 400
        assert resp.data["detail"] == "TOTP auth not found"

    def test_unverified_needs_no_token(self, client, generated, urls):
        resp = client.post(urls.disable)
        assert resp.status_code == 200
        assert TOTPAuth.objects.get(pk=generated.pk).otp_base32 is None

    def test_verified_requires_token(self, client, enrolled, urls):
        resp = client.post(urls.disable)
        assert resp.status_code == 400
        assert resp.data["detail"] == "A valid token is required to disable TOTP."
        assert TOTPAuth.objects.get(pk=enrolled.pk).otp_verified is True

    def test_wrong_token(self, client, enrolled, urls):
        resp = client.post(urls.disable, {"token": "000000"})
        assert resp.status_code == 400
        assert resp.data["detail"] == "Invalid token"
        assert TOTPAuth.objects.get(pk=enrolled.pk).otp_verified is True

    def test_valid_token_clears_everything(self, client, enrolled, urls, code):
        client.post(urls.backup, {"token": code(enrolled)})
        assert TOTPBackupCode.objects.filter(auth=enrolled).count() == 10
        resp = client.post(urls.disable, {"token": code(enrolled, 1)})
        assert resp.status_code == 200
        assert resp.data == {"detail": "TOTP disabled successfully"}
        enrolled.refresh_from_db()
        assert enrolled.otp_enabled is False
        assert enrolled.otp_verified is False
        assert enrolled.otp_base32 is None
        assert enrolled.last_used_step is None
        assert enrolled.last_used_at is None
        assert TOTPBackupCode.objects.filter(auth=enrolled).count() == 0

    def test_backup_code_can_disable(self, client, enrolled, urls, code):
        codes = client.post(urls.backup, {"token": code(enrolled)}).data["backup_codes"]
        resp = client.post(urls.disable, {"token": codes[0]})
        assert resp.status_code == 200

    def test_password_required_setting(self, client, enrolled, urls, code, settings):
        settings.TOTP_DISABLE_REQUIRES_PASSWORD = True
        resp = client.post(urls.disable, {"token": code(enrolled)})
        assert resp.status_code == 400
        assert "password" in resp.data
        resp = client.post(urls.disable, {"token": code(enrolled), "password": "wrong"})
        assert resp.status_code == 400
        resp = client.post(urls.disable, {"token": code(enrolled), "password": "testpass123"})
        assert resp.status_code == 200

    def test_re_enroll_after_disable(self, client, enrolled, urls, code):
        assert client.post(urls.disable, {"token": code(enrolled)}).status_code == 200
        assert client.post(urls.generate).status_code == 200


class TestValidate:
    def test_not_found(self, client, urls):
        resp = client.post(urls.validate, {"token": "123456"})
        assert resp.status_code == 400
        assert resp.data["detail"] == "TOTP auth not found"

    def test_not_enabled(self, client, generated, urls, code):
        resp = client.post(urls.validate, {"token": code(generated)})
        assert resp.status_code == 400
        assert resp.data["detail"] == "TOTP not enabled"

    def test_valid(self, client, enrolled, urls, code):
        resp = client.post(urls.validate, {"token": code(enrolled)})
        assert resp.status_code == 200
        assert resp.data == {"detail": "Token is valid", "method": "totp"}

    @pytest.mark.parametrize("token", ["000000", "abcdef", "12345", "", "ZZZZZ-ZZZZZ"])
    def test_invalid(self, client, enrolled, urls, token):
        resp = client.post(urls.validate, {"token": token})
        assert resp.status_code == 400

    def test_missing_token_field(self, client, enrolled, urls):
        resp = client.post(urls.validate, {})
        assert resp.status_code == 400
        assert "token" in resp.data


class TestBackupCodes:
    def test_requires_totp_code(self, client, enrolled, urls):
        resp = client.post(urls.backup, {"token": "000000"})
        assert resp.status_code == 400
        assert resp.data["detail"] == "Invalid token"

    def test_requires_enrollment(self, client, generated, urls, code):
        resp = client.post(urls.backup, {"token": code(generated)})
        assert resp.status_code == 400
        assert resp.data["detail"] == "TOTP not enabled"

    def test_issue_and_use(self, client, enrolled, urls, code):
        resp = client.post(urls.backup, {"token": code(enrolled)})
        assert resp.status_code == 200
        codes = resp.data["backup_codes"]
        assert len(codes) == 10
        assert all(len(c) == 11 and c[5] == "-" for c in codes)
        assert len(set(codes)) == 10
        # Only hashes are stored.
        stored = list(TOTPBackupCode.objects.values_list("code_hash", flat=True))
        assert all(c.replace("-", "") not in h for c in codes for h in stored)
        assert client.get(urls.status).data["backup_codes_remaining"] == 10

        resp = client.post(urls.validate, {"token": codes[0].lower().replace("-", " ")})
        assert resp.status_code == 200
        assert resp.data["method"] == "backup_code"
        assert client.get(urls.status).data["backup_codes_remaining"] == 9

        resp = client.post(urls.validate, {"token": codes[0]})
        assert resp.status_code == 400, "a backup code is single-use"

    def test_regenerate_replaces_old_codes(self, client, enrolled, urls, code):
        old = client.post(urls.backup, {"token": code(enrolled)}).data["backup_codes"]
        new = client.post(urls.backup, {"token": code(enrolled, 1)}).data["backup_codes"]
        assert set(old).isdisjoint(new)
        assert client.post(urls.validate, {"token": old[0]}).status_code == 400
        assert client.post(urls.validate, {"token": new[0]}).status_code == 200

    def test_backup_code_cannot_mint_backup_codes(self, client, enrolled, urls, code):
        codes = client.post(urls.backup, {"token": code(enrolled)}).data["backup_codes"]
        resp = client.post(urls.backup, {"token": codes[0]})
        assert resp.status_code == 400
        assert "token" in resp.data

    def test_count_setting(self, client, enrolled, urls, code, settings):
        settings.TOTP_BACKUP_CODE_COUNT = 4
        assert len(client.post(urls.backup, {"token": code(enrolled)}).data["backup_codes"]) == 4

    def test_disabled_by_setting(self, client, enrolled, urls, code, settings):
        settings.TOTP_BACKUP_CODES_ENABLED = False
        codes_resp = client.post(urls.backup, {"token": code(enrolled)})
        assert codes_resp.status_code == 400
        assert codes_resp.data["detail"] == "Backup codes are disabled."
        settings.TOTP_BACKUP_CODES_ENABLED = True
        codes = client.post(urls.backup, {"token": code(enrolled)}).data["backup_codes"]
        settings.TOTP_BACKUP_CODES_ENABLED = False
        assert client.post(urls.validate, {"token": codes[0]}).status_code == 400


class TestAuthenticationRequired:
    @pytest.mark.parametrize(
        "name, method",
        [
            ("generate", "post"),
            ("verify", "post"),
            ("status", "get"),
            ("disable", "post"),
            ("validate", "post"),
            ("backup", "post"),
        ],
    )
    def test_anonymous_is_rejected(self, db, urls, name, method):
        from rest_framework.test import APIClient

        resp = getattr(APIClient(), method)(getattr(urls, name), {"token": "123456"})
        assert resp.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)


class TestCustomDigits:
    def test_eight_digit_codes(self, client, user, urls, frozen, settings, code):
        settings.TOTP_DIGITS = 8
        client.post(urls.generate)
        auth = TOTPAuth.objects.get(user=user)
        token = code(auth)
        assert len(token) == 8
        assert client.post(urls.verify, {"token": "123456"}).status_code == 400
        assert client.post(urls.verify, {"token": token}).status_code == 200


class TestBackupCodeStorage:
    """Backup codes are stored as HMAC-SHA256 keyed with SECRET_KEY."""

    def test_stored_hash_is_keyed(self, client, enrolled, urls, code, settings):
        import hashlib

        codes = client.post(urls.backup, {"token": code(enrolled)}).data["backup_codes"]
        plain = codes[0].replace("-", "")
        stored = set(TOTPBackupCode.objects.values_list("code_hash", flat=True))
        assert all(h.startswith("hmac_sha256$") for h in stored)
        assert f"hmac_sha256${hashlib.sha256(plain.encode()).hexdigest()}" not in stored

    def test_secret_key_rotation_with_fallback(self, client, enrolled, urls, code, settings):
        codes = client.post(urls.backup, {"token": code(enrolled)}).data["backup_codes"]
        old_key = settings.SECRET_KEY
        settings.SECRET_KEY = "a-brand-new-secret-key"
        assert client.post(urls.validate, {"token": codes[0]}).status_code == 400
        settings.SECRET_KEY_FALLBACKS = [old_key]
        assert client.post(urls.validate, {"token": codes[0]}).status_code == 200


class TestDeprecatedSerializerNames:
    def test_old_names_still_import_with_warning(self):
        from drf_totp import serializers

        with pytest.warns(DeprecationWarning, match="TOTPStatusSerializer"):
            from drf_totp.serializers import TOTPAuthSerializer
        assert TOTPAuthSerializer is serializers.TOTPStatusSerializer
        with pytest.warns(DeprecationWarning, match="TOTPTokenSerializer"):
            from drf_totp.serializers import VerifyTOTPSerializer
        assert VerifyTOTPSerializer is serializers.TOTPTokenSerializer
        with pytest.raises(ImportError):
            from drf_totp.serializers import NoSuchSerializer  # noqa: F401
