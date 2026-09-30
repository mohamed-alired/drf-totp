from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone
from freezegun import freeze_time
from rest_framework.test import APIClient

from drf_totp import services
from drf_totp.models import TOTPAuth

FROZEN = "2026-01-01 12:00:00"
PASSWORD = "testpass123"


class Urls:
    generate = reverse("drf_totp:generate-otp")
    verify = reverse("drf_totp:verify-otp")
    status = reverse("drf_totp:otp-status")
    disable = reverse("drf_totp:disable-otp")
    validate = reverse("drf_totp:validate-otp")
    backup = reverse("drf_totp:backup-codes")
    protected = reverse("protected")
    enrolled_only = reverse("enrolled-only")


@pytest.fixture(autouse=True)
def clear_throttle_cache():
    """DRF throttles keep history in the cache, which outlives the test transaction."""
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def urls():
    return Urls


@pytest.fixture
def frozen():
    with freeze_time(FROZEN) as freezer:
        yield freezer


@pytest.fixture
def user(db):
    return get_user_model().objects.create_user(
        username="alice", email="alice@example.com", password=PASSWORD
    )


@pytest.fixture
def client(user):
    """API client authenticated as ``user`` without a session."""
    c = APIClient()
    c.force_authenticate(user=user)
    return c


@pytest.fixture
def session_client(user):
    """API client logged in through a real session (SessionAuthentication)."""
    c = APIClient()
    assert c.login(username=user.username, password=PASSWORD)
    return c


def code_for(auth, offset_steps=0, at=None):
    """The code an authenticator app would show ``offset_steps`` steps from now."""
    auth.refresh_from_db()
    when = (at or timezone.now()) + timedelta(seconds=30 * offset_steps)
    return services.build_totp(auth.otp_base32).at(when)


@pytest.fixture
def code():
    return code_for


@pytest.fixture
def generated(client, user, frozen, urls):
    resp = client.post(urls.generate)
    assert resp.status_code == 200, resp.data
    return TOTPAuth.objects.get(user=user)


@pytest.fixture
def enrolled(client, generated, frozen, urls):
    """A user who finished enrollment two steps ago, so codes for -1, 0 and +1 are all fresh."""
    frozen.move_to("2026-01-01 11:59:00")
    resp = client.post(urls.verify, {"token": code_for(generated)})
    assert resp.status_code == 200, resp.data
    frozen.move_to(FROZEN)
    cache.clear()  # the verify call above must not count against the throttle
    generated.refresh_from_db()
    return generated
