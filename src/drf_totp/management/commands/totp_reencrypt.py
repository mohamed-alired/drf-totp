from django.core.management.base import BaseCommand, CommandError
from django.db import models, transaction

from drf_totp import crypto
from drf_totp.models import TOTPAuth


class Command(BaseCommand):
    help = (
        "Re-save every TOTP secret with the current TOTP_ENCRYPTION_KEY. Use it after "
        "turning encryption on or rotating keys. With --decrypt, write secrets back as plaintext."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--decrypt",
            action="store_true",
            help="Store secrets as plaintext (the key must still be configured to read them).",
        )

    def handle(self, *args, **options):
        if not options["decrypt"] and crypto.get_fernet() is None:
            raise CommandError("TOTP_ENCRYPTION_KEY is not set; nothing to encrypt.")
        count = 0
        with transaction.atomic():
            for auth in TOTPAuth.objects.exclude(otp_base32__isnull=True).iterator():
                if options["decrypt"]:
                    # Bypass the field's encryption by using a plain CharField expression.
                    TOTPAuth.objects.filter(pk=auth.pk).update(
                        otp_base32=models.Value(auth.otp_base32, output_field=models.CharField())
                    )
                else:
                    auth.save(update_fields=["otp_base32"])
                count += 1
        verb = "Decrypted" if options["decrypt"] else "Re-encrypted"
        self.stdout.write(self.style.SUCCESS(f"{verb} {count} secret(s)."))
