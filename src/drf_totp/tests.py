from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from .models import TOTPAuth
import pyotp


class TOTPAuthViewsTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.User = get_user_model()
        self.user = self.User.objects.create_user(
            username="testuser", email="test@example.com", password="testpass123"
        )
        self.client.force_authenticate(user=self.user)

        self.generate_url = reverse("drf_totp:generate-otp")
        self.verify_url = reverse("drf_totp:verify-otp")
        self.status_url = reverse("drf_totp:otp-status")
        self.disable_url = reverse("drf_totp:disable-otp")
        self.validate_url = reverse("drf_totp:validate-otp")

    def test_generate_otp(self):
        response = self.client.post(self.generate_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("secret", response.data)
        self.assertIn("otpauth_url", response.data)

        auth = TOTPAuth.objects.get(user=self.user)
        auth.otp_verified = True
        auth.save()

        response = self.client.post(self.generate_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "TOTP already enabled and verified.")

        self.client.force_authenticate(user=None)
        response = self.client.post(self.generate_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_verify_otp(self):
        response = self.client.post(self.verify_url, {"token": "123456"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["detail"], "TOTP auth not found. Please generate TOTP first."
        )

        response = self.client.post(self.generate_url)
        auth = TOTPAuth.objects.get(user=self.user)
        totp = pyotp.TOTP(auth.otp_base32)
        valid_token = totp.now()

        response = self.client.post(self.verify_url, {"token": valid_token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "TOTP verified successfully")

        response = self.client.post(self.verify_url, {"token": "000000"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "Invalid token")

        response = self.client.post(self.verify_url, {"token": "12345"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_otp_status(self):
        response = self.client.get(self.status_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["otp_enabled"])
        self.assertFalse(response.data["otp_verified"])

        self.client.post(self.generate_url)
        auth = TOTPAuth.objects.get(user=self.user)
        totp = pyotp.TOTP(auth.otp_base32)
        self.client.post(self.verify_url, {"token": totp.now()})

        response = self.client.get(self.status_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["otp_enabled"])
        self.assertTrue(response.data["otp_verified"])

    def test_disable_otp(self):
        self.client.post(self.generate_url)
        auth = TOTPAuth.objects.get(user=self.user)
        totp = pyotp.TOTP(auth.otp_base32)
        self.client.post(self.verify_url, {"token": totp.now()})

        response = self.client.post(self.disable_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "TOTP disabled successfully")

        auth.refresh_from_db()
        self.assertFalse(auth.otp_enabled)
        self.assertFalse(auth.otp_verified)
        self.assertIsNone(auth.otp_base32)
        self.assertIsNone(auth.otp_auth_url)

    def test_validate_otp(self):
        response = self.client.post(self.validate_url, {"token": "123456"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "TOTP auth not found")

        self.client.post(self.generate_url)
        auth = TOTPAuth.objects.get(user=self.user)
        totp = pyotp.TOTP(auth.otp_base32)
        self.client.post(self.verify_url, {"token": totp.now()})

        valid_token = totp.now()
        response = self.client.post(self.validate_url, {"token": valid_token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "Token is valid")

        response = self.client.post(self.validate_url, {"token": "000000"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "Invalid token")

    def test_authentication_required(self):
        self.client.force_authenticate(user=None)
        urls = [
            self.generate_url,
            self.verify_url,
            self.status_url,
            self.disable_url,
            self.validate_url,
        ]

        for url in urls:
            response = self.client.post(url)
            self.assertEqual(
                response.status_code,
                status.HTTP_403_FORBIDDEN,
                f"URL {url} should require authentication",
            )
