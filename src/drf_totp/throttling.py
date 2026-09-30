from rest_framework.settings import api_settings
from rest_framework.throttling import SimpleRateThrottle

from . import conf


class TOTPThrottle(SimpleRateThrottle):
    """Per-user rate limit for token submission endpoints.

    The rate comes from ``REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]["drf_totp"]``
    when present, otherwise from ``TOTP_THROTTLE_RATE`` (default ``"5/min"``).
    A rate of ``None`` disables throttling.
    """

    scope = "drf_totp"

    def get_rate(self):
        rates = api_settings.DEFAULT_THROTTLE_RATES or {}
        if self.scope in rates:
            return rates[self.scope]
        return conf.get_setting("TOTP_THROTTLE_RATE")

    def get_cache_key(self, request, view):
        user = getattr(request, "user", None)
        authenticated = user is not None and user.is_authenticated
        ident = user.pk if authenticated else self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}
