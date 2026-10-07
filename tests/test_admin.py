import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone

from drf_totp.models import TOTPAuth
from drf_totp.services import SESSION_KEY

pytestmark = pytest.mark.django_db


@pytest.fixture
def admin_client(db):
    from django.test import Client

    admin = get_user_model().objects.create_superuser("root", "root@example.com", "pw")
    c = Client()
    c.force_login(admin)
    return c


class TestTOTPAuthAdmin:
    def test_changelist(self, admin_client, enrolled):
        resp = admin_client.get(reverse("admin:drf_totp_totpauth_changelist"))
        assert resp.status_code == 200
        assert b"alice" in resp.content
        assert enrolled.otp_base32.encode() not in resp.content

    def test_change_page_hides_secret(self, admin_client, enrolled):
        resp = admin_client.get(reverse("admin:drf_totp_totpauth_change", args=[enrolled.pk]))
        assert resp.status_code == 200
        assert enrolled.otp_base32.encode() not in resp.content
        assert b"otp_base32" not in resp.content

    def test_no_delete(self, admin_client, enrolled):
        resp = admin_client.get(reverse("admin:drf_totp_totpauth_delete", args=[enrolled.pk]))
        assert resp.status_code == 403
        resp = admin_client.post(
            reverse("admin:drf_totp_totpauth_changelist"),
            {"action": "delete_selected", "_selected_action": [enrolled.pk]},
        )
        assert TOTPAuth.objects.filter(pk=enrolled.pk).exists()
        changelist = admin_client.get(reverse("admin:drf_totp_totpauth_changelist"))
        assert b'value="delete_selected"' not in changelist.content

    def test_changelist_query_count_is_flat(self, admin_client, enrolled):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        url = reverse("admin:drf_totp_totpauth_changelist")
        with CaptureQueriesContext(connection) as one:
            admin_client.get(url)
        for i in range(5):
            u = get_user_model().objects.create_user(f"u{i}", f"u{i}@example.com", "pw")
            TOTPAuth.objects.create(user=u, otp_base32="JBSWY3DPEHPK3PXP", otp_verified=True)
        with CaptureQueriesContext(connection) as six:
            admin_client.get(url)
        assert len(six) == len(one)

    def test_no_add(self, admin_client):
        resp = admin_client.get(reverse("admin:drf_totp_totpauth_add"))
        assert resp.status_code == 403

    def test_reset_action(self, admin_client, enrolled):
        resp = admin_client.post(
            reverse("admin:drf_totp_totpauth_changelist"),
            {"action": "reset_totp", "_selected_action": [enrolled.pk]},
            follow=True,
        )
        assert resp.status_code == 200
        enrolled.refresh_from_db()
        assert enrolled.otp_verified is False and enrolled.otp_base32 is None

    def test_reset_action_keeps_the_admins_own_stamp(self, admin_client, enrolled):
        """Regression: resetting another user must not log the admin out of 2FA."""
        admin_id = get_user_model().objects.get(username="root").pk
        session = admin_client.session
        session[SESSION_KEY] = {"user": str(admin_id), "at": 1767268800}
        session.save()
        admin_client.post(
            reverse("admin:drf_totp_totpauth_changelist"),
            {"action": "reset_totp", "_selected_action": [enrolled.pk]},
        )
        assert TOTPAuth.objects.get(pk=enrolled.pk).otp_verified is False
        assert admin_client.session[SESSION_KEY]["user"] == str(admin_id)

    def test_unlock_action(self, admin_client, enrolled):
        enrolled.failed_attempts = 4
        enrolled.locked_until = timezone.now() + timezone.timedelta(hours=1)
        enrolled.save()
        admin_client.post(
            reverse("admin:drf_totp_totpauth_changelist"),
            {"action": "unlock", "_selected_action": [enrolled.pk]},
            follow=True,
        )
        auth = TOTPAuth.objects.get(pk=enrolled.pk)
        assert auth.failed_attempts == 0 and auth.locked_until is None
