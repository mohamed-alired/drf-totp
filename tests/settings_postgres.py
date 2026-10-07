"""Test settings backed by PostgreSQL, so SELECT ... FOR UPDATE is real.

    pytest --ds=tests.settings_postgres

Connection details come from PG* environment variables with local defaults.
"""

import os

from .settings import *  # noqa: F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("PGDATABASE", "drf_totp"),
        "USER": os.environ.get("PGUSER", "drf"),
        "PASSWORD": os.environ.get("PGPASSWORD", "drf"),
        "HOST": os.environ.get("PGHOST", "127.0.0.1"),
        "PORT": os.environ.get("PGPORT", "5432"),
        "TEST": {"NAME": os.environ.get("PGDATABASE", "drf_totp") + "_test"},
    }
}
