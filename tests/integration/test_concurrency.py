"""Concurrency tests. They need a database with real row locks, so they run on PostgreSQL only."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.db import connection, connections

from drf_totp import services
from drf_totp.exceptions import TOTPLocked
from drf_totp.models import TOTPAuth, TOTPBackupCode

pytestmark = [pytest.mark.django_db(transaction=True), pytest.mark.postgres]


@pytest.fixture(autouse=True)
def require_postgres():
    if connection.vendor != "postgresql":
        pytest.skip("row locking is only real on PostgreSQL")


def run_parallel(fn, n, *args):
    """Run ``fn`` in ``n`` threads, each with its own DB connection, starting together."""
    barrier = threading.Barrier(n)

    def wrapped(*a):
        try:
            barrier.wait()
            return fn(*a)
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=n) as pool:
        return list(pool.map(lambda _: wrapped(*args), range(n)))


@pytest.fixture
def enrolled_committed(user):
    """An enrolled user whose rows are committed, so other threads can see them."""
    auth, secret, _ = services.setup_totp(user)
    services.confirm_totp(auth, services.build_totp(secret).now())
    TOTPAuth.objects.filter(pk=auth.pk).update(last_used_step=None)
    auth.refresh_from_db()
    return auth


def test_same_totp_code_is_consumed_exactly_once(enrolled_committed, settings):
    settings.TOTP_THROTTLE_RATE = None
    code = services.build_totp(enrolled_committed.otp_base32).now()

    def attempt():
        auth = TOTPAuth.objects.get(pk=enrolled_committed.pk)
        return services.verify_totp_token(auth, code)

    results = run_parallel(attempt, 12)
    assert results.count(True) == 1, results
    # Replays prove possession and are not counted as failures.
    assert TOTPAuth.objects.get(pk=enrolled_committed.pk).failed_attempts == 0


def test_same_backup_code_is_consumed_exactly_once(enrolled_committed):
    codes = services.generate_backup_codes(enrolled_committed)

    def attempt():
        auth = TOTPAuth.objects.get(pk=enrolled_committed.pk)
        return services.use_backup_code(auth, codes[0])

    results = run_parallel(attempt, 12)
    assert results.count(True) == 1, results
    assert TOTPBackupCode.objects.filter(auth=enrolled_committed, used_at__isnull=True).count() == 9


def test_concurrent_backup_code_issue_leaves_exactly_one_live_set(enrolled_committed):
    def issue():
        auth = TOTPAuth.objects.get(pk=enrolled_committed.pk)
        return services.generate_backup_codes(auth)

    sets = run_parallel(issue, 8)
    live = TOTPBackupCode.objects.filter(auth=enrolled_committed, used_at__isnull=True)
    assert live.count() == 10
    auth = TOTPAuth.objects.get(pk=enrolled_committed.pk)
    usable_sets = [s for s in sets if services.use_backup_code(auth, s[0])]
    assert len(usable_sets) == 1, "only the last writer's set may be valid"


def test_lockout_counter_is_consistent_under_concurrent_failures(enrolled_committed, settings):
    settings.TOTP_MAX_FAILED_ATTEMPTS = 5
    settings.TOTP_LOCKOUT_SECONDS = 300

    def attempt():
        auth = TOTPAuth.objects.get(pk=enrolled_committed.pk)
        try:
            return services.verify_totp_token(auth, "000000")
        except TOTPLocked:
            return "locked"

    results = run_parallel(attempt, 20)
    assert True not in results
    auth = TOTPAuth.objects.get(pk=enrolled_committed.pk)
    assert auth.is_locked
    # Exactly 5 failures were counted before the lock, the rest hit the lock or were counted
    # into a new cycle; either way the counter never exceeds the threshold.
    assert 0 <= auth.failed_attempts < 5
    assert results.count("locked") >= 1


def test_concurrent_setup_creates_a_single_row(user):
    def setup():
        return services.setup_totp(user)[0].pk

    pks = run_parallel(setup, 8)
    assert len(set(pks)) == 1
    assert TOTPAuth.objects.filter(user=user).count() == 1
