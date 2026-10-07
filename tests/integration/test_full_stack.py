"""Integration tests: the real middleware stack, CSRF enforcement, signals and logging together."""

import logging

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.urls import reverse
from rest_framework.test import APIClient

from drf_totp import services, signals
from drf_totp.models import TOTPAuth, TOTPBackupCode

pytestmark = pytest.mark.django_db


class TestCsrfEnforcedSessionFlow:
    """SessionAuthentication enforces CSRF on unsafe methods, so a browser must send the token."""

    @pytest.fixture
    def browser(self, user):
        c = APIClient(enforce_csrf_checks=True)
        assert c.login(username=user.username, password="testpass123")
        return c

    def test_post_without_csrf_token_is_rejected(self, browser, urls, frozen):
        resp = browser.post(urls.generate)
        assert resp.status_code == 403
        assert "CSRF" in str(resp.data["detail"])
        assert not TOTPAuth.objects.exists()

    def test_full_lifecycle_with_csrf_token(self, browser, urls, frozen, code, user):
        browser.get("/api-auth/login/")  # renders {% csrf_token %}, which sets the cookie
        token = browser.cookies["csrftoken"].value
        hdr = {"HTTP_X_CSRFTOKEN": token}

        assert browser.post(urls.generate, **hdr).status_code == 200
        auth = TOTPAuth.objects.get(user=user)
        assert browser.post(urls.verify, {"token": code(auth)}, **hdr).status_code == 200
        assert browser.get(urls.protected).status_code == 200
        frozen.tick(30)
        resp = browser.post(urls.backup, {"token": code(auth)}, **hdr)
        assert resp.status_code == 200
        codes = resp.data["backup_codes"]
        frozen.tick(30)
        assert browser.post(urls.validate, {"token": code(auth)}, **hdr).status_code == 200
        assert browser.post(urls.disable, {"token": codes[0]}, **hdr).status_code == 200
        assert browser.get(urls.status).data["otp_verified"] is False
        assert browser.get(urls.protected).status_code == 200


class TestAuditTrail:
    """Signals and log lines together give a complete audit trail of a user's 2FA lifecycle."""

    def test_signals_and_logs_cover_every_event(
        self, client, urls, frozen, code, user, caplog, settings
    ):
        settings.TOTP_THROTTLE_RATE = None
        events = []

        def record(label, key=None):
            return lambda sender, **kw: events.append(f"{label}:{kw[key]}" if key else label)

        receivers = {
            signals.totp_enabled: record("enabled"),
            signals.totp_validated: record("validated", "method"),
            signals.totp_validation_failed: record("failed", "method"),
            signals.backup_codes_generated: record("backup", "count"),
            signals.totp_disabled: record("disabled"),
        }
        for sig, fn in receivers.items():
            sig.connect(fn)
        try:
            with caplog.at_level(logging.INFO, logger="drf_totp"):
                client.post(urls.generate)
                auth = TOTPAuth.objects.get(user=user)
                client.post(urls.verify, {"token": "000000"})
                client.post(urls.verify, {"token": code(auth)})
                frozen.tick(30)
                codes = client.post(urls.backup, {"token": code(auth)}).data["backup_codes"]
                client.post(urls.validate, {"token": "ZZZZZ-ZZZZZ"})
                client.post(urls.validate, {"token": codes[0]})
                frozen.tick(30)
                client.post(urls.disable, {"token": code(auth)})
        finally:
            for sig, fn in receivers.items():
                sig.disconnect(fn)

        assert events == [
            "failed:totp",
            "validated:totp",
            "enabled",
            "validated:totp",
            "backup:10",
            "failed:backup_code",
            "validated:backup_code",
            "validated:totp",
            "disabled",
        ]
        messages = [r.getMessage() for r in caplog.records if r.name == "drf_totp"]
        assert any("validation failed" in m for m in messages)
        assert any("TOTP enabled" in m for m in messages)
        assert any("Backup codes generated" in m for m in messages)
        assert any("TOTP disabled" in m for m in messages)
        assert auth.otp_base32 not in caplog.text
        assert all(c.replace("-", "") not in caplog.text for c in codes)


class TestEncryptionRollout:
    """Turning encryption on in a running deployment: old rows keep working, re-encrypt, rotate."""

    def test_rollout_and_rotation(self, client, urls, frozen, code, user, settings):
        from cryptography.fernet import Fernet

        settings.TOTP_ENCRYPTION_KEY = None
        client.post(urls.generate)
        auth = TOTPAuth.objects.get(user=user)
        assert client.post(urls.verify, {"token": code(auth)}).status_code == 200

        key1 = Fernet.generate_key().decode()
        settings.TOTP_ENCRYPTION_KEY = key1  # deployment turns encryption on
        frozen.tick(30)
        assert client.post(urls.validate, {"token": code(auth)}).status_code == 200  # legacy row
        call_command("totp_reencrypt")
        frozen.tick(30)
        assert client.post(urls.validate, {"token": code(auth)}).status_code == 200

        key2 = Fernet.generate_key().decode()
        settings.TOTP_ENCRYPTION_KEY = [key2, key1]  # rotation starts
        call_command("totp_reencrypt")
        settings.TOTP_ENCRYPTION_KEY = key2  # old key retired
        frozen.tick(30)
        assert client.post(urls.validate, {"token": code(auth)}).status_code == 200
        assert client.get(urls.status).status_code == 200


class TestAdminIntegration:
    def test_reset_from_admin_then_user_reenrolls(self, client, enrolled, urls, code, user, frozen):
        from django.test import Client

        admin = get_user_model().objects.create_superuser("root", "r@example.com", "pw")
        ac = Client()
        ac.force_login(admin)
        client.post(urls.backup, {"token": code(enrolled)})
        assert TOTPBackupCode.objects.filter(auth=enrolled).count() == 10

        ac.post(
            reverse("admin:drf_totp_totpauth_changelist"),
            {"action": "reset_totp", "_selected_action": [enrolled.pk]},
        )
        assert client.get(urls.status).data == {
            **client.get(urls.status).data,
            "otp_verified": False,
            "backup_codes_remaining": 0,
        }
        frozen.tick(30)
        assert client.post(urls.generate).status_code == 200
        enrolled.refresh_from_db()
        assert client.post(urls.verify, {"token": code(enrolled)}).status_code == 200


class TestUserDeletion:
    def test_cascade_removes_totp_and_backup_codes(self, client, enrolled, urls, code, user):
        client.post(urls.backup, {"token": code(enrolled)})
        user.delete()
        assert not TOTPAuth.objects.exists()
        assert not TOTPBackupCode.objects.exists()


class TestServiceLayerWithoutRequest:
    """Everything works from a shell / Celery task with no request object."""

    def test_headless_lifecycle(self, user, frozen):
        from django.utils import timezone

        auth, secret, uri = services.setup_totp(user)
        assert secret in uri
        totp = services.build_totp(secret)
        # Codes are computed from aware UTC time, as an authenticator app does. (pyotp's
        # ``now()`` uses naive local time, which under a frozen clock and Django's default
        # TIME_ZONE would be interpreted in the wrong zone.)
        services.confirm_totp(auth, totp.at(timezone.now()))
        frozen.tick(30)
        assert services.validate_token(auth, totp.at(timezone.now())) == "totp"
        codes = services.generate_backup_codes(auth)
        assert services.validate_token(auth, codes[0]) == "backup_code"
        services.disable_totp(auth)
        assert services.user_has_totp(user) is False
