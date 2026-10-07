"""End-to-end tests over real HTTP against pytest-django's live server.

Codes are computed from the returned secret the way an authenticator app would,
against real time, so the suite first aligns itself inside a 30-second step.
"""

import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pyotp
import pytest
import requests
from django.contrib.auth import get_user_model
from django.db import connection

pytestmark = [pytest.mark.django_db(transaction=True), pytest.mark.e2e]

PASSWORD = "e2e-pass-123"


def code_at(secret, offset_steps=0):
    when = datetime.now(timezone.utc) + timedelta(seconds=30 * offset_steps)
    return pyotp.TOTP(secret).at(when)


def align_to_step(max_seconds_in=18):
    """Wait until we are early enough in the current step for -1/0/+1 codes to stay valid."""
    while time.time() % 30 > max_seconds_in:
        time.sleep(0.25)


@pytest.fixture
def base(live_server):
    return live_server.url


@pytest.fixture
def api(base):
    def make(username):
        get_user_model().objects.get_or_create(
            username=username, defaults={"email": f"{username}@example.com"}
        )
        u = get_user_model().objects.get(username=username)
        u.set_password(PASSWORD)
        u.save()
        s = requests.Session()
        s.auth = (username, PASSWORD)
        s.base = base
        return s

    return make


def u(session, name):
    return f"{session.base}/auth/otp/{name}/"


class TestBasicAuthApi:
    def test_every_endpoint(self, api, settings):
        settings.TOTP_THROTTLE_RATE = "30/min"
        align_to_step()
        s = api("alice")

        r = requests.get(u(s, "status"))
        assert r.status_code in (401, 403)

        assert s.get(u(s, "status")).json()["otp_verified"] is False
        r = s.post(u(s, "generate"))
        assert r.status_code == 200
        secret, uri = r.json()["secret"], r.json()["otpauth_url"]
        assert uri.startswith("otpauth://totp/drftotp:alice%40example.com?")
        status = s.get(u(s, "status"))
        assert secret not in status.text and "otp_auth_url" not in status.json()

        assert s.post(u(s, "verify"), json={"token": "12345"}).status_code == 400
        assert s.post(u(s, "verify"), json={"token": "000000"}).json()["detail"] == "Invalid token"
        first = code_at(secret, -1)
        assert s.post(u(s, "verify"), json={"token": first}).status_code == 200
        assert s.post(u(s, "verify"), json={"token": code_at(secret)}).status_code == 400
        assert s.post(u(s, "generate")).status_code == 400
        assert s.post(u(s, "validate"), json={"token": first}).status_code == 400  # replay

        now_code = code_at(secret)
        r = s.post(u(s, "validate"), json={"token": now_code})
        assert r.status_code == 200 and r.json()["method"] == "totp"
        assert s.post(u(s, "validate"), json={"token": now_code}).status_code == 400

        r = s.post(u(s, "backup-codes"), json={"token": code_at(secret, +1)})
        assert r.status_code == 200
        codes = r.json()["backup_codes"]
        assert len(codes) == 10 and all(re.fullmatch(r"[A-Z2-9]{5}-[A-Z2-9]{5}", c) for c in codes)
        r = s.post(u(s, "validate"), json={"token": codes[0].lower()})
        assert r.status_code == 200 and r.json()["method"] == "backup_code"
        assert s.post(u(s, "validate"), json={"token": codes[0]}).status_code == 400
        assert s.post(u(s, "backup-codes"), json={"token": codes[1]}).status_code == 400
        st = s.get(u(s, "status")).json()
        assert st["otp_verified"] and st["backup_codes_remaining"] == 9 and st["last_used_at"]

        assert s.post(u(s, "disable")).status_code == 400
        assert s.post(u(s, "disable"), json={"token": "000000"}).status_code == 400
        assert s.post(u(s, "disable"), json={"token": codes[2]}).status_code == 200
        st = s.get(u(s, "status")).json()
        assert st["otp_verified"] is False and st["backup_codes_remaining"] == 0
        r = s.post(u(s, "generate"))
        assert r.status_code == 200 and r.json()["secret"] != secret

    def test_throttle_is_per_user_over_http(self, api, settings):
        settings.TOTP_THROTTLE_RATE = "5/min"
        bob, carol = api("bob"), api("carol")
        bob.post(u(bob, "generate"))
        statuses = [
            bob.post(u(bob, "verify"), json={"token": "000000"}).status_code for _ in range(6)
        ]
        assert statuses[:5] == [400] * 5 and statuses[5] == 429
        carol.post(u(carol, "generate"))
        assert carol.post(u(carol, "verify"), json={"token": "000000"}).status_code == 400

    def test_lockout_over_http(self, api, settings):
        settings.TOTP_THROTTLE_RATE = None
        settings.TOTP_MAX_FAILED_ATTEMPTS = 3
        align_to_step()
        s = api("dave")
        secret = s.post(u(s, "generate")).json()["secret"]
        assert s.post(u(s, "verify"), json={"token": code_at(secret, -1)}).status_code == 200
        for _ in range(3):
            assert s.post(u(s, "validate"), json={"token": "000000"}).status_code == 400
        r = s.post(u(s, "validate"), json={"token": code_at(secret)})
        assert r.status_code == 429
        assert "Too many failed attempts" in r.json()["detail"]


def csrf_token(session):
    """The most recent csrftoken cookie (the jar may hold one per domain spelling)."""
    return [c.value for c in session.cookies if c.name == "csrftoken"][-1]


def session_login(base, username):
    s = requests.Session()
    s.get(f"{base}/api-auth/login/")
    r = s.post(
        f"{base}/api-auth/login/",
        data={"username": username, "password": PASSWORD, "csrfmiddlewaretoken": csrf_token(s)},
        headers={"Referer": f"{base}/api-auth/login/"},
        allow_redirects=False,
    )
    assert r.status_code == 302 and "sessionid" in [c.name for c in s.cookies], r.status_code
    s.headers.update({"X-CSRFToken": csrf_token(s), "Referer": base})
    s.base = base
    return s


class TestSessionFlow:
    def test_csrf_stamp_and_permission(self, api, base, settings):
        settings.TOTP_THROTTLE_RATE = "30/min"
        api("erin")  # creates the user
        align_to_step()
        s = session_login(base, "erin")
        assert s.get(f"{base}/protected/").status_code == 200

        no_csrf = requests.Session()
        no_csrf.cookies = s.cookies
        assert no_csrf.post(u(s, "generate")).status_code == 403

        secret = s.post(u(s, "generate")).json()["secret"]
        assert s.post(u(s, "verify"), json={"token": code_at(secret)}).status_code == 200
        assert s.get(f"{base}/protected/").status_code == 200

        s2 = session_login(base, "erin")
        r = s2.get(f"{base}/protected/")
        assert r.status_code == 403 and "Second factor" in r.json()["detail"]
        assert s2.post(u(s2, "validate"), json={"token": code_at(secret, +1)}).status_code == 200
        assert s2.get(f"{base}/protected/").status_code == 200

    def test_admin_pages(self, api, base):
        s = api("frank")
        secret = s.post(u(s, "generate")).json()["secret"]
        admin = get_user_model().objects.create_superuser("root", "r@example.com", PASSWORD)
        a = session_login(base, admin.username)
        r = a.get(f"{base}/admin/drf_totp/totpauth/")
        assert r.status_code == 200 and "frank" in r.text and secret not in r.text
        m = re.search(r'href="/admin/drf_totp/totpauth/(\d+)/change/"', r.text)
        r = a.get(f"{base}/admin/drf_totp/totpauth/{m.group(1)}/change/")
        assert r.status_code == 200 and secret not in r.text and "otp_base32" not in r.text
        assert a.get(f"{base}/admin/drf_totp/totpauth/add/").status_code == 403
        assert a.get(f"{base}/admin/drf_totp/totpauth/{m.group(1)}/delete/").status_code == 403


@pytest.mark.postgres
class TestHttpConcurrency:
    """Parallel requests through the whole stack. Needs real row locks, so PostgreSQL only."""

    @pytest.fixture(autouse=True)
    def require_postgres(self):
        if connection.vendor != "postgresql":
            pytest.skip("needs PostgreSQL for real row locks")

    def test_parallel_validate_accepts_a_code_once(self, api, settings):
        settings.TOTP_THROTTLE_RATE = None
        align_to_step()
        s = api("grace")
        secret = s.post(u(s, "generate")).json()["secret"]
        assert s.post(u(s, "verify"), json={"token": code_at(secret, -1)}).status_code == 200
        token = code_at(secret)
        with ThreadPoolExecutor(max_workers=10) as pool:
            codes = list(
                pool.map(
                    lambda _: s.post(u(s, "validate"), json={"token": token}).status_code,
                    range(10),
                )
            )
        assert codes.count(200) == 1 and codes.count(400) == 9, codes
