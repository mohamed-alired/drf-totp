from django.urls import path
from . import views

app_name = 'drf_totp'

urlpatterns = [
    path('otp/generate/', views.GenerateOTP.as_view(), name='generate-otp'),
    path('otp/verify/', views.VerifyOTP.as_view(), name='verify-otp'),
    path('otp/status/', views.OTPStatus.as_view(), name='otp-status'),
    path('otp/disable/', views.DisableOTP.as_view(), name='disable-otp'),
    path('otp/validate/', views.ValidateOTP.as_view(), name='validate-otp'),
]