# Package imports
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from rest_framework.views import exception_handler
from rest_framework import status
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework.exceptions import NotAuthenticated
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.conf import settings
from django.utils.http import base36_to_int
from datetime import datetime
from django.conf import settings
from django.utils.crypto import constant_time_compare
from django.utils.http import base36_to_int
import secrets
from django.core.mail import send_mail


def get_response_schema(schema, message, status_code):
    
    return Response({
        'message': message,
        'status': status_code,
        'results': schema,
    }, status=status_code)


def custom_token_exception_handler(exc, context):

    response = exception_handler(exc, context)

    if (isinstance(exc, InvalidToken)) or (isinstance(exc, NotAuthenticated)):

        return get_response_schema( {}, get_global_error_messages('INVALID_TOKEN'), status.HTTP_401_UNAUTHORIZED,)

    return response


def get_tokens_for_user(user):

    refresh = RefreshToken.for_user(user)

    return str(refresh), str(refresh.access_token)


def get_global_success_messages(key):

    data = {

        'RECORD_RETRIEVED': 'The record was successfully retrieved.',
        'RECORD_CREATED': 'The record was successfully created.',
        'LOGGED_OUT': "User logged out.",
        'LOGGED_IN': 'Logged in successfully.',
        'VERIFIED_SUCCESSFULLY': 'User verified successfully.',
        'PASSWORD_UPDATED': 'Password updated successfully.',

    }   
    return data.get(key)


def get_global_error_messages(key):

    data = {
        
        'BAD_REQUEST': 'Bad request.',
        'NOT_FOUND': 'User not found.',
        'INVALID_TOKEN': 'Token is invalid or expired. Please try again.',
        'INVALID_REFRESH_TOKEN': 'Refresh token is invalid or expired. Please try again.',
        'USER_NOT_ACTIVE': 'User is not active.',
        'UNAUTHORIZED': 'Invalid credentials.',
        'UNVERIFIED_ACCOUNT': 'Account is un-verified.',
        'INVALID_LINK': 'Invalid verification link.',
        'FAIL_VERIFICATION_MAIL': 'Failed to send email. Please try again later.',
        'PASSWORD_REQUIRED': 'Password can not be empty',
        
    }
    return data.get(key)


def get_serializer_error_msg(error): 

    return {settings.REST_FRAMEWORK["NON_FIELD_ERRORS_KEY"]: error}


class CustomTokenGenerator(PasswordResetTokenGenerator):

    def make_token(self, user, expiration=None):

        if expiration is None:
            expiration = self._num_seconds(self._now()) + settings.PASSWORD_RESET_TIMEOUT
        else:
            expiration = self._num_seconds(expiration)
        return self._make_token_with_timestamp(
            user,
            expiration,
            self.secret,
        )

    def check_token(self, user, token):

        if not (user and token):
            return False
        
        try:
            ts_b36, _ = token.split("-")

        except ValueError:
            return False

        try:

            ts = base36_to_int(ts_b36)

        except ValueError:
            return False

        for secret in [self.secret, *self.secret_fallbacks]:

            if constant_time_compare(
                self._make_token_with_timestamp(user, ts, secret),
                token,
            ):
                break
        else:
            return False

        if (self._num_seconds(self._now()) - ts) > settings.PASSWORD_RESET_TIMEOUT:

            return False

        return True

    def _make_hash_value(self, user, timestamp):

        login_timestamp = (
            ""
            if user.last_login is None
            else user.last_login.replace(microsecond=0, tzinfo=None)
        )
        email_field = user.get_email_field_name()

        email = getattr(user, email_field, "") or ""

        return f"{user.pk}{user.password}{login_timestamp}{timestamp}{email}"

    def _num_seconds(self, dt):

        return int((dt - datetime(2001, 1, 1)).total_seconds())

    def _now(self):

        return datetime.now()


custom_token_generator = CustomTokenGenerator()


def send_email_with_link(request, user, subject, email_message, url_name):
    current_site = get_current_site(request)
    domain = current_site.domain

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = custom_token_generator.make_token(user)
    
    verification_url = reverse(url_name)
    verification_link = f"http://{domain}{verification_url}?uidb64={uid}&token={token}"
    
    email_message = email_message.format(user=user.business_name, verification_link=verification_link)
    
    email = EmailMultiAlternatives(
        subject,
        strip_tags(email_message),
        settings.EMAIL_HOST_USER,
        [user.email],
    )

    email.attach_alternative(email_message, "text/html")

    email.send()
    
    return "Email sent successfully"


def send_verification_email(request, user):

    subject = "Verify Your Email"

    email_message = (
        "<p>Hi {user},</p>"
        "<p>Please verify your account by visiting the following link:</p>"
        "<p><a href='{verification_link}'>{verification_link}</a></p>"
        "<p>Thank you!</p>"
    )

    return send_email_with_link(request, user, subject, email_message, 'verify-email')


def send_forgot_password_email_business_user(request, user):

    subject = "Reset Your Password"

    email_message = (
        "<p>Hi {user},</p>"
        "<p>Click bellow link to redirect on forgot password page.</p>"
        "<p><a href='{verification_link}'>{verification_link}</a></p>"
        "<p>Thank you!</p>"
    )
    
    return send_email_with_link(request, user, subject, email_message, 'forgot-password-business-user')


def generate_auth_token():
    return secrets.token_urlsafe(32)


def send_auth_token_email(user, token, base_url):

    subject = 'Login Authentication Link'
    message = f'Click the following link to log in: {base_url}/business-user/authenticate/{token}/'
    from_email = 'yourmail@gmail.com'
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list)

def wrong_login_attempt(user):

    subject = 'Wrong login attempt'
    message = f'Wrong login attempt'
    from_email = 'yourmail@gmail.com'
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list)
