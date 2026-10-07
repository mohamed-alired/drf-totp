from django.contrib import admin
from django.urls import include, path

from . import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("auth/", include("drf_totp.urls")),
    path("api-auth/", include("rest_framework.urls")),
    path("protected/", views.ProtectedView.as_view(), name="protected"),
    path("enrolled-only/", views.EnrolledOnlyView.as_view(), name="enrolled-only"),
]
