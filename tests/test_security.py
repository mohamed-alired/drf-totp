import logging
from unittest import mock

import pytest
from django.db import DatabaseError, connection
from rest_framework.test import APIClient

from drf_totp import services, signals
from drf_totp.models import TOTPAuth

pytestmark = pytest.mark.django_db


class TestReplay:
    def test_same_code_twice_is_rejected(self, client, enrolled, urls, code):
        token = code(enrolled)
        assert client.post(urls.validate, {"token": token}).status_code == 200
        resp = client.post(urls.validate, {"token": token})
        assert resp.status_code == 400
        assert resp.data["detail"] == "Invalid token"

    def test_older_step_rejected_after_newer_used(self, client, enrolled, urls, code):
        assert client.post(urls.validate, {"token": code(enrolled, +1)}).status_code == 200
        assert client.post(urls.validate, {"token": code(enrolled, 0)}).status_code == 400
        assert client.post(urls.validate, {"token": code(enrolled, -1)}).status_code == 400

    def test_enrollment_code_cannot_be_replayed_on_validate(self, client, generated, urls, code):
        token = code(generated)
        assert client.post(urls.verify, {"token": token}).status_code == 200
        assert client.post(urls.validate, {"token": token}).status_code == 400
        assert client.post(urls.validate, {"token": code(generated, 1)}).status_code == 200

    def test_new_secret_resets_replay_state(self, client, enrolled, urls, code):
        assert client.post(urls.validate, {"token": code(enrolled)}).status_code == 200
        assert client.post(urls.disable, {"token": code(enrolled)}).status_code == 400  # replay
        assert client.post(urls.disable, {"token": code(enrolled, 1)}).status_code == 200
        client.post(urls.generate)
        assert TOTPAuth.objects.get(pk=enrolled.pk).last_used_step is None


class TestWindow:
    def test_default_window_accepts_one_step_of_drift(self, client, enrolled, urls, code):
        assert client.post(urls.validate, {"token": code(enrolled, -1)}).status_code == 200

    def test_default_window_rejects_two_steps(self, client, enrolled, urls, code):
        assert client.post(urls.validate, {"token": code(enrolled, -2)}).status_code == 400
        assert client.post(urls.validate, {"token": code(enrolled, +2)}).status_code == 400

    def test_future_step_within_window(self, client, enrolled, urls, code):
        assert client.post(urls.validate, {"token": code(enrolled, +1)}).status_code == 200

    def test_zero_window(self, client, enrolled, urls, code, settings):
        settings.TOTP_VALID_WINDOW = 0
        assert client.post(urls.validate, {"token": code(enrolled, -1)}).status_code == 400
        assert client.post(urls.validate, {"token": code(enrolled, 0)}).status_code == 200


class TestThrottle:
    def test_default_rate_limits_to_five_per_minute(self, client, enrolled, urls):
        for _ in range(5):
            assert client.post(urls.validate, {"token": "000000"}).status_code == 400
        resp = client.post(urls.validate, {"token": "000000"})
        assert resp.status_code == 429

    def test_throttle_is_per_user(self, client, enrolled, urls, django_user_model):
        from rest_framework.test import APIClient

        for _ in range(6):
            client.post(urls.validate, {"token": "000000"})
        other = django_user_model.objects.create_user("bob", "bob@example.com", "pw")
        c = APIClient()
        c.force_authenticate(user=other)
        assert c.post(urls.validate, {"token": "000000"}).status_code == 400

    def test_throttle_covers_verify_disable_and_backup(self, client, generated, urls):
        for _ in range(5):
            client.post(urls.verify, {"token": "000000"})
        assert client.post(urls.verify, {"token": "000000"}).status_code == 429
        assert client.post(urls.disable, {"token": "000000"}).status_code == 429
        assert client.post(urls.backup, {"token": "000000"}).status_code == 429

    def test_generate_and_status_are_not_throttled(self, client, urls, frozen):
        for _ in range(8):
            assert client.post(urls.generate).status_code == 200
            assert client.get(urls.status).status_code == 200

    def test_setting_can_disable(self, client, enrolled, urls, settings):
        settings.TOTP_THROTTLE_RATE = None
        for _ in range(8):
            assert client.post(urls.validate, {"token": "000000"}).status_code == 400

    def test_drf_scope_takes_precedence(self, client, enrolled, urls, settings):
        settings.REST_FRAMEWORK = {
            "DEFAULT_THROTTLE_RATES": {"drf_totp": "2/min"},
        }
        from rest_framework.settings import api_settings

        api_settings.reload()
        try:
            client.post(urls.validate, {"token": "000000"})
            client.post(urls.validate, {"token": "000000"})
            assert client.post(urls.validate, {"token": "000000"}).status_code == 429
        finally:
            api_settings.reload()


class TestLockout:
    def test_lockout_after_max_failures(self, client, enrolled, urls, code, settings, frozen):
        settings.TOTP_MAX_FAILED_ATTEMPTS = 3
        settings.TOTP_LOCKOUT_SECONDS = 120
        settings.TOTP_THROTTLE_RATE = None
        for _ in range(3):
            assert client.post(urls.validate, {"token": "000000"}).status_code == 400
        resp = client.post(urls.validate, {"token": code(enrolled)})
        assert resp.status_code == 429
        assert resp.data["detail"] == "Too many failed attempts. Try again later."
        enrolled.refresh_from_db()
        assert enrolled.is_locked

        frozen.tick(121)
        assert client.post(urls.validate, {"token": code(enrolled)}).status_code == 200
        enrolled.refresh_from_db()
        assert enrolled.failed_attempts == 0
        assert enrolled.locked_until is None

    def test_success_resets_counter(self, client, enrolled, urls, code, settings):
        settings.TOTP_MAX_FAILED_ATTEMPTS = 3
        settings.TOTP_THROTTLE_RATE = None
        client.post(urls.validate, {"token": "000000"})
        client.post(urls.validate, {"token": "000000"})
        assert client.post(urls.validate, {"token": code(enrolled)}).status_code == 200
        assert TOTPAuth.objects.get(pk=enrolled.pk).failed_attempts == 0
        client.post(urls.validate, {"token": "000000"})
        client.post(urls.validate, {"token": "000000"})
        assert client.post(urls.validate, {"token": code(enrolled, 1)}).status_code == 200

    def test_backup_code_failures_count(self, client, enrolled, urls, settings):
        settings.TOTP_MAX_FAILED_ATTEMPTS = 2
        settings.TOTP_THROTTLE_RATE = None
        client.post(urls.validate, {"token": "AAAAA-AAAAA"})
        client.post(urls.validate, {"token": "AAAAA-AAAAA"})
        assert client.post(urls.validate, {"token": "AAAAA-AAAAA"}).status_code == 429

    def test_disabled_by_default(self, client, enrolled, urls, code, settings):
        settings.TOTP_THROTTLE_RATE = None
        for _ in range(20):
            client.post(urls.validate, {"token": "000000"})
        assert client.post(urls.validate, {"token": code(enrolled)}).status_code == 200


class TestSignals:
    @pytest.fixture
    def received(self):
        calls = []

        def make(name):
            def handler(sender, **kwargs):
                calls.append((name, kwargs))

            return handler

        handlers = {
            "enabled": make("enabled"),
            "disabled": make("disabled"),
            "validated": make("validated"),
            "failed": make("failed"),
            "backup": make("backup"),
        }
        signals.totp_enabled.connect(handlers["enabled"])
        signals.totp_disabled.connect(handlers["disabled"])
        signals.totp_validated.connect(handlers["validated"])
        signals.totp_validation_failed.connect(handlers["failed"])
        signals.backup_codes_generated.connect(handlers["backup"])
        yield calls
        signals.totp_enabled.disconnect(handlers["enabled"])
        signals.totp_disabled.disconnect(handlers["disabled"])
        signals.totp_validated.disconnect(handlers["validated"])
        signals.totp_validation_failed.disconnect(handlers["failed"])
        signals.backup_codes_generated.disconnect(handlers["backup"])

    def test_lifecycle_signals(
        self, client, generated, urls, code, user, received, frozen, settings
    ):
        settings.TOTP_THROTTLE_RATE = None  # six token submissions in one test
        assert client.post(urls.verify, {"token": "000000"}).status_code == 400
        assert client.post(urls.verify, {"token": code(generated)}).status_code == 200
        frozen.tick(30)
        assert client.post(urls.validate, {"token": code(generated)}).status_code == 200
        frozen.tick(30)
        resp = client.post(urls.backup, {"token": code(generated)})
        assert resp.status_code == 200
        backup_code = resp.data["backup_codes"][0]
        assert client.post(urls.validate, {"token": backup_code}).status_code == 200
        frozen.tick(30)
        assert client.post(urls.disable, {"token": code(generated)}).status_code == 200

        names = [n for n, _ in received]
        assert names == [
            "failed",
            "validated",
            "enabled",
            "validated",
            "validated",
            "backup",
            "validated",
            "validated",
            "disabled",
        ]
        assert all(kw["user"] == user for _, kw in received)
        assert all(kw["request"] is not None for _, kw in received)
        methods = [kw["method"] for n, kw in received if n == "validated"]
        assert methods == ["totp", "totp", "totp", "backup_code", "totp"]
        assert received[5][1]["count"] == 10


class TestLogging:
    def test_failure_is_logged_without_secrets(self, client, enrolled, urls, caplog):
        with caplog.at_level(logging.WARNING, logger="drf_totp"):
            client.post(urls.validate, {"token": "000000"})
        assert any("validation failed" in r.getMessage() for r in caplog.records)
        assert enrolled.otp_base32 not in caplog.text
        assert "000000" not in caplog.text


@pytest.fixture
def atomic_requests():
    connection.settings_dict["ATOMIC_REQUESTS"] = True
    yield
    connection.settings_dict["ATOMIC_REQUESTS"] = False


@pytest.mark.django_db(transaction=True)
class TestAtomicRequests:
    """Regression: under ATOMIC_REQUESTS the failure counter must survive the 400 response."""

    def _client(self, django_user_model):
        user = django_user_model.objects.create_user("carol", "c@example.com", "pw")
        services.setup_totp(user)
        TOTPAuth.objects.filter(user=user).update(otp_verified=True, otp_enabled=True)
        c = APIClient()
        c.force_authenticate(user=user)
        return user, c

    def test_lockout_persists(self, atomic_requests, settings, django_user_model, urls):
        settings.TOTP_MAX_FAILED_ATTEMPTS = 3
        settings.TOTP_THROTTLE_RATE = None
        user, c = self._client(django_user_model)
        for _ in range(3):
            assert c.post(urls.validate, {"token": "000000"}).status_code == 400
        auth = TOTPAuth.objects.get(user=user)
        assert auth.locked_until is not None
        assert c.post(urls.validate, {"token": "000000"}).status_code == 429

    def test_failure_counter_persists(self, atomic_requests, settings, django_user_model, urls):
        settings.TOTP_THROTTLE_RATE = None
        user, c = self._client(django_user_model)
        c.post(urls.validate, {"token": "000000"})
        c.post(urls.validate, {"token": "AAAAA-AAAAA"})
        assert TOTPAuth.objects.get(user=user).failed_attempts == 2

    def test_views_opt_out_of_atomic_requests(self):
        from django.urls import resolve

        for name in ("generate", "verify", "status", "disable", "validate", "backup-codes"):
            func = resolve(f"/auth/otp/{name}/").func
            assert "default" in getattr(func, "_non_atomic_requests", set()), name


class TestEnabledFlagDesync:
    """Regression: only otp_verified decides enrollment; otp_enabled is a deprecated mirror."""

    def test_validate_and_disable_work_when_flags_disagree(self, client, enrolled, urls, code):
        TOTPAuth.objects.filter(pk=enrolled.pk).update(otp_enabled=False)
        assert client.post(urls.validate, {"token": code(enrolled)}).status_code == 200
        assert client.post(urls.disable, {"token": code(enrolled, 1)}).status_code == 200


class TestDisableIsAtomic:
    """Regression: a failure while deleting backup codes must leave TOTP enabled."""

    def test_rollback_on_backup_code_delete_failure(self, enrolled):
        services.generate_backup_codes(enrolled)
        with (
            mock.patch("django.db.models.query.QuerySet.delete", side_effect=DatabaseError("boom")),
            pytest.raises(DatabaseError),
        ):
            services.disable_totp(enrolled)
        fresh = TOTPAuth.objects.get(pk=enrolled.pk)
        assert fresh.otp_verified is True
        assert fresh.otp_base32
        assert fresh.backup_codes.count() == 10
