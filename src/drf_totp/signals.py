"""Signals emitted by drf-totp.

All signals are sent with ``sender=TOTPAuth`` and the keyword arguments
``user`` and ``request`` (``request`` may be ``None`` when called outside a view).
"""

from django.dispatch import Signal

#: TOTP was confirmed and enabled for ``user``.
totp_enabled = Signal()
#: TOTP was disabled for ``user``.
totp_disabled = Signal()
#: A token was accepted. Extra kwarg ``method`` is ``"totp"`` or ``"backup_code"``.
totp_validated = Signal()
#: A token was rejected. Extra kwarg ``method`` as above.
totp_validation_failed = Signal()
#: A fresh set of backup codes was issued. Extra kwarg ``count``.
backup_codes_generated = Signal()
