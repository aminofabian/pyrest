# core/api_urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import api
from . import views

urlpatterns = [
    path('register/', api.register_api, name='api_register'),
    path('login/', api.login_api, name='api_login'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('user/profile/', api.user_profile, name='user_profile'),
    path('user/me/', api.user_me, name='user_me'),
    path('dashboard/data/', views.dashboard_data, name='api_dashboard_data'),
    path('test/', api.test_api, name='test_api'),
]
