"""Same suite, but with naive local datetimes in a non-UTC zone (USE_TZ=False, Asia/Tokyo)."""

from .settings import *  # noqa: F401,F403

USE_TZ = False
TIME_ZONE = "Asia/Tokyo"
