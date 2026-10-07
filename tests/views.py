from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from drf_totp.permissions import IsTOTPEnrolled, IsTOTPVerified


class ProtectedView(APIView):
    permission_classes = [IsAuthenticated, IsTOTPVerified]

    def get(self, request):
        return Response({"ok": True})


class EnrolledOnlyView(APIView):
    permission_classes = [IsAuthenticated, IsTOTPEnrolled]

    def get(self, request):
        return Response({"ok": True})
