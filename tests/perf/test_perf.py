"""Performance guards: query budgets per endpoint, behaviour at scale, and a small load test."""

import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext

from drf_totp import services
from drf_totp.models import TOTPAuth, TOTPBackupCode

pytestmark = pytest.mark.perf


def count_queries(fn):
    with CaptureQueriesContext(connection) as ctx:
        fn()
    return len(ctx)


@pytest.mark.django_db
class TestQueryBudgets:
    """Each endpoint must stay within a fixed number of queries (savepoints included)."""

    # Measured on SQLite and PostgreSQL (savepoints count as queries). A rise is a regression.
    BUDGET = {
        "status_empty": 1,
        "status": 2,
        "generate": 5,
        "verify": 12,
        "validate_totp": 10,
        "validate_backup": 11,
        "backup_codes": 16,
        "disable": 15,
        "protected_view": 2,
    }

    def test_budgets(self, client, user, urls, frozen, code, settings):
        settings.TOTP_THROTTLE_RATE = None
        measured = {}
        measured["status_empty"] = count_queries(lambda: client.get(urls.status))
        measured["generate"] = count_queries(lambda: client.post(urls.generate))
        auth = TOTPAuth.objects.get(user=user)
        measured["verify"] = count_queries(lambda: client.post(urls.verify, {"token": code(auth)}))
        measured["status"] = count_queries(lambda: client.get(urls.status))
        frozen.tick(30)
        measured["validate_totp"] = count_queries(
            lambda: client.post(urls.validate, {"token": code(auth)})
        )
        frozen.tick(30)
        resp = {}
        measured["backup_codes"] = count_queries(
            lambda: resp.update(client.post(urls.backup, {"token": code(auth)}).data)
        )
        measured["validate_backup"] = count_queries(
            lambda: client.post(urls.validate, {"token": resp["backup_codes"][0]})
        )
        measured["protected_view"] = count_queries(lambda: client.get(urls.protected))
        frozen.tick(30)
        measured["disable"] = count_queries(
            lambda: client.post(urls.disable, {"token": code(auth)})
        )
        over = {k: (v, self.BUDGET[k]) for k, v in measured.items() if v > self.BUDGET[k]}
        assert not over, f"query budget exceeded (measured, budget): {over}; all={measured}"


@pytest.mark.django_db
class TestScale:
    """Behaviour must not degrade with the number of enrolled users or backup codes."""

    @pytest.fixture
    def many_rows(self, django_user_model):
        users = django_user_model.objects.bulk_create(
            [django_user_model(username=f"u{i}", email=f"u{i}@example.com") for i in range(2000)]
        )
        users = list(django_user_model.objects.filter(username__startswith="u"))
        auths = TOTPAuth.objects.bulk_create(
            [
                TOTPAuth(user=u, otp_base32="JBSWY3DPEHPK3PXP", otp_verified=True, otp_enabled=True)
                for u in users
            ]
        )
        auths = list(TOTPAuth.objects.filter(user__in=users))
        TOTPBackupCode.objects.bulk_create(
            [
                TOTPBackupCode(auth=a, code_hash=services._make_code_hash(f"CODE{i:06d}"))
                for a in auths
                for i in range(10)
            ],
            batch_size=5000,
        )
        return auths

    def test_queries_and_latency_are_flat(self, client, enrolled, urls, code, many_rows, frozen):
        q_status = count_queries(lambda: client.get(urls.status))
        assert q_status <= 2
        start = time.perf_counter()
        for _ in range(20):
            assert client.get(urls.status).status_code == 200
        per_call = (time.perf_counter() - start) / 20
        assert per_call < 0.05, f"status took {per_call * 1000:.1f} ms with 20k backup codes"

        codes = client.post(urls.backup, {"token": code(enrolled)}).data["backup_codes"]
        start = time.perf_counter()
        assert client.post(urls.validate, {"token": codes[0]}).status_code == 200
        assert time.perf_counter() - start < 0.1, "backup-code lookup must be indexed, not a scan"

    def test_admin_changelist_is_flat(self, many_rows, django_user_model):
        from django.test import Client
        from django.urls import reverse

        admin = django_user_model.objects.create_superuser("root", "r@example.com", "pw")
        c = Client()
        c.force_login(admin)
        url = reverse("admin:drf_totp_totpauth_changelist")
        q = count_queries(lambda: c.get(url))
        assert q <= 12, f"admin changelist issued {q} queries for a 100-row page"


class TestLoad:
    """A short load test through real HTTP. Fails on any 5xx or on poor tail latency."""

    pytestmark = [pytest.mark.django_db(transaction=True), pytest.mark.load]

    @pytest.fixture(autouse=True)
    def require_postgres(self):
        if connection.vendor != "postgresql":
            pytest.skip("concurrent load needs PostgreSQL (SQLite serialises writers)")

    def test_mixed_load(self, live_server, settings):
        settings.TOTP_THROTTLE_RATE = None
        base = live_server.url
        users = []
        for i in range(8):
            u = get_user_model().objects.create_user(f"load{i}", f"load{i}@example.com", "pw")
            auth, secret, _ = services.setup_totp(u)
            services.confirm_totp(auth, services.build_totp(secret).now())
            s = requests.Session()
            s.auth = (u.username, "pw")
            users.append(s)

        def worker(idx):
            s = users[idx % len(users)]
            latencies, statuses = [], []
            for n in range(40):
                t0 = time.perf_counter()
                if n % 3 == 0:
                    r = s.get(f"{base}/auth/otp/status/")
                elif n % 3 == 1:
                    r = s.post(f"{base}/auth/otp/validate/", json={"token": "000000"})
                else:
                    r = s.get(f"{base}/protected/")
                latencies.append(time.perf_counter() - t0)
                statuses.append(r.status_code)
            return latencies, statuses

        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        elapsed = time.perf_counter() - t0
        lat = sorted(x for lats, _ in results for x in lats)
        statuses = [x for _, s in results for x in s]
        total = len(statuses)
        p50, p95, p99 = (lat[int(len(lat) * q)] for q in (0.50, 0.95, 0.99))
        print(
            f"\nload: {total} requests, {total / elapsed:.0f} req/s, "
            f"p50 {p50 * 1000:.0f} ms, p95 {p95 * 1000:.0f} ms, p99 {p99 * 1000:.0f} ms, "
            f"status counts {dict(sorted({s: statuses.count(s) for s in set(statuses)}.items()))}"
        )
        assert not [s for s in statuses if s >= 500], "server errors under load"
        assert statuses.count(200) + statuses.count(400) + statuses.count(403) == total
        assert p95 < 1.0, f"p95 latency {p95:.2f}s"
        assert statistics.mean(lat) < 0.5
