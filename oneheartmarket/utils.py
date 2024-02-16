# Package imports
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from rest_framework.views import exception_handler
from rest_framework import status
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework.exceptions import NotAuthenticated
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags


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
        'LOGGED_OUT': "User logged out",
        'LOGGED_IN': 'Logged in successFully',
        'VERIFIED_SUCCESSFULLY': 'User verified successfully'

    }   
    return data.get(key)


def get_global_error_messages(key):

    data = {

        'BAD_REQUEST': 'Bad request.',
        'NOT_FOUND': 'Resource not found.',
        'INVALID_TOKEN': 'Token is invalid or expired. Please try again.',
        'USER_NOT_ACTIVE': 'User is not active',
        'UNAUTHORIZED': 'Invalid credentials.',
        'UNVERIFIED_ACCOUNT': 'Account is un-verified',
        'INVALID_LINK': 'Invalid verification link',

    }
    return data.get(key)


def get_serializer_error_msg(error): 

    return {settings.REST_FRAMEWORK["NON_FIELD_ERRORS_KEY"]: error}


def send_verification_email(request, user):

    try:

        current_site = get_current_site(request)

        domain = current_site.domain

        uid = urlsafe_base64_encode(force_bytes(user.pk))

        token = default_token_generator.make_token(user)

        verification_url = reverse('verify-email')

        verification_link = f"http://{domain}{verification_url}?uidb64={uid}&token={token}"

        email_subject = "Verify Your Email"

        email_message = (
            f"<p>Hi {user.business_name},</p>"
            "<p>Please verify your account by visiting the following link:</p>"
            f"<p><a href='{verification_link}'>{verification_link}</a></p>"
            "<p>Thank you!</p>"
        )

        email = EmailMultiAlternatives(
            email_subject,
            strip_tags(email_message),
            settings.EMAIL_HOST_USER,
            [user.email],
        )

        email.attach_alternative(email_message, "text/html")

        email.send()
        
        return "Verify mail sent successfully"
    
    except Exception as e:

        print('➡ oneheartmarket/oneheartmarket/utils.py:108 e:', e)
