from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from business.views import (
    GetBusinessUserView,
    CreateBusinessUserView,
    LoginBusinessUser,
    LogoutBusinessUser,
    VerifyEmailAPIView,
    SendMailForgotPasswordBusinessUser,
    VerifyEmailForgotPasswordAPIView,
    ForgotPasswordBusinessUser,
    SignUpView,
    forgot_password_business_user,
    password_forgot_request,
    custom_success_page,
    TokenLoginView,
)

urlpatterns = [

    path('get-business-user/<int:id>/', GetBusinessUserView.as_view(), name='get-business-user'),
    path('create-business-user/', CreateBusinessUserView.as_view(), name='create-business-user'),

    path('login-business-user/', LoginBusinessUser.as_view(), name='login-business-user'),
    path('logout-business-user/', LogoutBusinessUser.as_view(), name='logout-business-user'),
    
    path('verify-email/', VerifyEmailAPIView.as_view(), name='verify-email'), 

    path('send-mail-forgotpassword-businessuser/', SendMailForgotPasswordBusinessUser.as_view(), name='send-mail-forgotpassword-businessuser'),
    path('Verify-Email-Forgot-Password-businessuser/', VerifyEmailForgotPasswordAPIView.as_view(), name='Verify-Email-Forgot-Password-businessuser'), 

    path('Forgot-Password-businessuser/', ForgotPasswordBusinessUser.as_view(), name='Forgot-Password-businessuser'), 

    path('refreshtoken/', TokenRefreshView.as_view(), name='token_refresh'),


    path('signup/', SignUpView.as_view(), name='signup'),

    path('authenticate/<str:token>/', TokenLoginView.as_view(), name='token_login'),

    #template

    path('custom_success_page/', custom_success_page, name='custom_success_page'),
    path('request-forgot-password/', password_forgot_request, name='request-forgot-password'),
    path('forgot-password-business-user/', forgot_password_business_user, name='forgot-password-business-user'),

]
