"""Upgrade path: a database created by drf-totp 0.1.x migrates to 0.2 with its data intact."""

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

pytestmark = pytest.mark.django_db(transaction=True)


def migrate_to(target):
    executor = MigrationExecutor(connection)
    executor.migrate([("drf_totp", target)])
    executor.loader.build_graph()
    return executor.loader.project_state([("drf_totp", target)]).apps


def test_0_1_rows_survive_the_upgrade(settings):
    old_apps = migrate_to("0001_initial")
    OldAuth = old_apps.get_model("drf_totp", "TOTPAuth")
    user = get_user_model().objects.create_user("legacy", "legacy@example.com", "pw")
    OldAuth.objects.create(
        user_id=user.pk,
        otp_enabled=True,
        otp_verified=True,
        otp_base32="JBSWY3DPEHPK3PXP",
        otp_auth_url="otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
    )

    new_apps = migrate_to("0002_security_hardening")
    NewAuth = new_apps.get_model("drf_totp", "TOTPAuth")
    row = NewAuth.objects.get(user_id=user.pk)
    assert row.otp_verified is True
    assert row.otp_base32 == "JBSWY3DPEHPK3PXP"
    assert row.last_used_step is None and row.failed_attempts == 0 and row.locked_until is None
    assert not hasattr(row, "otp_auth_url")

    # The real model (with the encrypting field) reads the legacy plaintext row too.
    from drf_totp import services
    from drf_totp.models import TOTPAuth

    auth = TOTPAuth.objects.get(user=user)
    assert auth.otp_base32 == "JBSWY3DPEHPK3PXP"
    assert services.user_has_totp(user) is True
    assert services.validate_token(auth, services.build_totp(auth.otp_base32).now()) == "totp"


def test_migrations_roll_back():
    migrate_to("0001_initial")
    with connection.cursor() as c:
        description = connection.introspection.get_table_description(c, "drf_totp_totpauth")
    cols = {col.name for col in description}
    assert "otp_auth_url" in cols and "last_used_step" not in cols
    migrate_to("0002_security_hardening")
