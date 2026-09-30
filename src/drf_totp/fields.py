from django.db import models

from . import crypto


class EncryptedCharField(models.CharField):
    """A ``CharField`` transparently encrypted at rest when ``TOTP_ENCRYPTION_KEY`` is set.

    Equality lookups against the column are not supported once encryption is on,
    because every write produces a fresh ciphertext.
    """

    description = "CharField encrypted at rest with Fernet when TOTP_ENCRYPTION_KEY is set"

    def from_db_value(self, value, expression, connection):
        return crypto.decrypt(value)

    def get_prep_value(self, value):
        return crypto.encrypt(super().get_prep_value(value))
