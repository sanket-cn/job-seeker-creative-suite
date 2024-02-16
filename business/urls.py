from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from business.views import (
    GetBusinessUserView,
    CreateBusinessUserView,
    LoginBusinessUser,
    LogoutBusinessUser,
    VerifyEmailAPIView
)

urlpatterns = [

    path('get-business-user/<int:id>/', GetBusinessUserView.as_view(), name='get-business-user'),
    path('create-business-user/', CreateBusinessUserView.as_view(), name='create-business-user'),

    path('login-business-user/', LoginBusinessUser.as_view(), name='login-business-user'),
    path('logout-business-user/', LogoutBusinessUser.as_view(), name='logout-business-user'),
    
    path('verify-email/', VerifyEmailAPIView.as_view(), name='verify-email'),  # Use the new API view

    path('refreshtoken/', TokenRefreshView.as_view(), name='token_refresh'),

]
