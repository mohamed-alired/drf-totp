import pyotp
import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from rest_framework.authentication import BaseAuthentication
from rest_framework.test import APIClient

from drf_totp import services
from drf_totp import views as totp_views
from drf_totp.models import TOTPAuth
from drf_totp.services import SESSION_KEY
from tests.views import ProtectedView

pytestmark = pytest.mark.django_db


def enroll_via_session(session_client, urls, code, user):
    from drf_totp.models import TOTPAuth

    session_client.post(urls.generate)
    auth = TOTPAuth.objects.get(user=user)
    resp = session_client.post(urls.verify, {"token": code(auth)})
    assert resp.status_code == 200, resp.data
    return auth


class TestIsTOTPVerified:
    def test_anonymous_rejected(self, db, urls):
        assert APIClient().get(urls.protected).status_code in (401, 403)

    def test_user_without_totp_allowed(self, session_client, urls):
        assert session_client.get(urls.protected).status_code == 200

    def test_generated_but_unverified_allowed(self, session_client, urls, frozen):
        session_client.post(urls.generate)
        assert session_client.get(urls.protected).status_code == 200

    def test_enrolled_session_is_stamped_by_verify(self, session_client, urls, code, user, frozen):
        enroll_via_session(session_client, urls, code, user)
        assert session_client.session[SESSION_KEY] == {"user": str(user.pk), "at": 1767268800}
        assert session_client.get(urls.protected).status_code == 200

    def test_fresh_session_requires_validate(self, session_client, urls, code, user, frozen):
        auth = enroll_via_session(session_client, urls, code, user)
        session_client.logout()
        assert session_client.login(username="alice", password="testpass123")
        resp = session_client.get(urls.protected)
        assert resp.status_code == 403
        assert resp.data["detail"] == "Second factor verification required."
        assert session_client.post(urls.validate, {"token": code(auth, 1)}).status_code == 200
        assert session_client.get(urls.protected).status_code == 200

    def test_stamp_expires(self, session_client, urls, code, user, frozen, settings):
        settings.TOTP_SESSION_MAX_AGE = 60
        enroll_via_session(session_client, urls, code, user)
        assert session_client.get(urls.protected).status_code == 200
        frozen.tick(61)
        assert session_client.get(urls.protected).status_code == 403

    def test_disable_clears_stamp(self, session_client, urls, code, user, frozen):
        auth = enroll_via_session(session_client, urls, code, user)
        assert SESSION_KEY in session_client.session
        session_client.post(urls.disable, {"token": code(auth, 1)})
        assert SESSION_KEY not in session_client.session
        assert session_client.get(urls.protected).status_code == 200  # no TOTP any more

    def test_new_client_without_stamped_session_is_rejected(self, user, enrolled, urls):
        # A different client (or a token/JWT setup) has no stamped session.
        fresh = APIClient()
        fresh.force_authenticate(user=user)
        assert fresh.get(urls.protected).status_code == 403

    def test_custom_verified_check(self, client, enrolled, urls, settings):
        settings.TOTP_VERIFIED_CHECK = "tests.test_permissions.always_true"
        assert client.get(urls.protected).status_code == 200
        settings.TOTP_VERIFIED_CHECK = lambda request: False
        assert client.get(urls.protected).status_code == 403


def always_true(request):
    return True


class TestIsTOTPEnrolled:
    def test_requires_enrollment(self, client, urls):
        assert client.get(urls.enrolled_only).status_code == 403

    def test_enrolled_allowed(self, client, enrolled, urls):
        assert client.get(urls.enrolled_only).status_code == 200


class TestSessionHelpers:
    def test_no_request(self):
        services.mark_session_verified(None, 1)
        services.clear_session_verified(None)
        assert services.is_session_verified(None) is False

    def test_request_without_session(self, rf):
        request = rf.get("/")
        services.mark_session_verified(request, 1)
        assert services.is_session_verified(request) is False

    def test_legacy_or_foreign_stamp_formats_are_ignored(self, rf, user):
        request = rf.get("/")
        request.user = user
        request.session = {SESSION_KEY: 1767268800}  # bare timestamp
        assert services.is_session_verified(request) is False
        request.session = {SESSION_KEY: {"user": str(user.pk + 1), "at": 1767268800}}
        assert services.is_session_verified(request) is False
        request.session = {SESSION_KEY: {"user": str(user.pk), "at": 1767268800}}
        assert services.is_session_verified(request) is True


class HeaderAuth(BaseAuthentication):
    """Token-style authentication: the user comes from a header, not the session."""

    def authenticate(self, request):
        username = request.META.get("HTTP_X_USER")
        if not username:
            return None
        return (get_user_model().objects.get(username=username), None)


class TestStampIsBoundToUser:
    """Regression: a stamp earned by one user must not satisfy IsTOTPVerified for another."""

    def test_other_users_stamp_in_same_cookie_is_rejected(self, db, monkeypatch):
        monkeypatch.setattr(totp_views.ValidateOTP, "authentication_classes", [HeaderAuth])
        monkeypatch.setattr(ProtectedView, "authentication_classes", [HeaderAuth])
        User = get_user_model()
        attacker = User.objects.create_user("attacker", "a@example.com", "pw")
        victim = User.objects.create_user("victim", "v@example.com", "pw")
        totps = {}
        for u in (attacker, victim):
            secret = pyotp.random_base32()
            TOTPAuth.objects.create(user=u, otp_base32=secret, otp_verified=True, otp_enabled=True)
            totps[u.username] = pyotp.TOTP(secret)

        browser = Client()  # one cookie jar shared by both credentials
        resp = browser.post(
            "/auth/otp/validate/", {"token": totps["attacker"].now()}, HTTP_X_USER="attacker"
        )
        assert resp.status_code == 200
        assert browser.get("/protected/", HTTP_X_USER="attacker").status_code == 200
        assert browser.get("/protected/", HTTP_X_USER="victim").status_code == 403

        resp = browser.post(
            "/auth/otp/validate/", {"token": totps["victim"].now()}, HTTP_X_USER="victim"
        )
        assert resp.status_code == 200
        assert browser.get("/protected/", HTTP_X_USER="victim").status_code == 200
        # The stamp now belongs to the victim, so the attacker's stamp is gone.
        assert browser.get("/protected/", HTTP_X_USER="attacker").status_code == 403
