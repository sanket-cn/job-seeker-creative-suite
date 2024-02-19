from rest_framework.generics import GenericAPIView
from rest_framework import status
from django.shortcuts import render
from django.db import transaction
from django.contrib.auth import (
    login,
    logout,
    authenticate
)
from django.utils.http import urlsafe_base64_decode

from business.models import (
    BusinessUser
)

from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from oneheartmarket.utils import (
    get_global_success_messages,
    get_global_error_messages,
    get_response_schema,
    get_serializer_error_msg,
    get_tokens_for_user,
    send_verification_email,
    send_forgot_password_email_business_user,
    custom_token_generator
)

from business.serializers import (
    BusinessUserSerializer,
    CreateBusinessUserSerializer,
)

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


class GetBusinessUserView(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, id):

        business_user = BusinessUser.objects.filter(
            id=id, 
        ).first()

        if business_user is None:

            return None  

        return business_user

    def get(self, request, id):

        business_user = self.get_object(id)

        if business_user is None: 

            return get_response_schema({},  get_global_error_messages('NOT_FOUND'), status.HTTP_200_OK,)

        serializer = BusinessUserSerializer(business_user)

        return get_response_schema(serializer.data, get_global_success_messages('RECORD_RETRIEVED') , status.HTTP_404_NOT_FOUND)


class CreateBusinessUserView(GenericAPIView):
    
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['business_name', 'email', 'password', 'business_category', 'business_location'],
            properties={
                'business_name': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
                'business_category': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    enum=[choice[0] for choice in BusinessUser.CategoriesType.choices],
                    description="Business category"
                ),
                'business_location': openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                    'latitude': openapi.Schema(type=openapi.TYPE_STRING, format='decimal'),
                    'longitude': openapi.Schema(type=openapi.TYPE_STRING, format='decimal'),
                    'address': openapi.Schema(type=openapi.TYPE_STRING),
                }),
            }
        )
    )
    def post(self, request):

        with transaction.atomic():

            data = request.data

            data["business_user_role"] = BusinessUser.RoleType.BUSINESSUSER

            data["is_staff"] = True

            serializer = CreateBusinessUserSerializer(data=data)

            if serializer.is_valid(): 

                user = serializer.save()
                
                send_verification_email(request, user)

                return get_response_schema(serializer.data, get_global_success_messages('RECORD_CREATED'), status.HTTP_201_CREATED,)
            
            transaction.set_rollback(True)                        

        return get_response_schema(get_serializer_error_msg(serializer.errors), get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)


class LoginBusinessUser(GenericAPIView):    

    permission_classes = [AllowAny]
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            }
        )
    )
    def post(self, request):

        data = request.data

        email = data["email"]

        password = data["password"]

        user = authenticate(request=request, username=email, password=password)

        if user == None:

            return get_response_schema( get_global_error_messages('NOT_FOUND'), get_global_error_messages('BAD_REQUEST'), status.HTTP_404_NOT_FOUND)
        
        if not user.is_active:

            return get_response_schema( get_global_error_messages('USER_NOT_ACTIVE'), get_global_error_messages('BAD_REQUEST'), status.HTTP_403_FORBIDDEN)
        
        if user.is_verified == False:

            return get_response_schema( get_global_error_messages('UNVERIFIED_ACCOUNT'), get_global_error_messages('BAD_REQUEST'), status.HTTP_400_BAD_REQUEST)

        login(request, user)
        
        refresh, access = get_tokens_for_user(user) 

        data.pop('password', None)

        result = data

        result["refresh"] = refresh

        result["access"] = access

        return get_response_schema(result, get_global_success_messages('LOGGED_IN'), status.HTTP_200_OK)
    

class LogoutBusinessUser(GenericAPIView):
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body = openapi.Schema(
            type = openapi.TYPE_OBJECT,
            properties = {
                'refresh': openapi.Schema(type=openapi.TYPE_STRING),
            }
        )
    )
    def post(self, request):

        try:
            refresh_token = RefreshToken(request.data['refresh'])

            refresh_token.blacklist()

            logout(request) 

            return get_response_schema( {}, get_global_success_messages('LOGGED_OUT'), status.HTTP_200_OK)

        except:

            return get_response_schema( {}, get_global_success_messages('LOGGED_OUT'), status.HTTP_200_OK)
        

class VerifyEmailAPIView(GenericAPIView):
    
    def get(self, request):

        try:
            uidb64 = request.GET.get('uidb64')

            token = request.GET.get('token')
            
            if not uidb64 or not token:

                return get_response_schema({}, get_global_error_messages('INVALID_LINK'), status.HTTP_400_BAD_REQUEST)
            
            try:

                uid = urlsafe_base64_decode(uidb64).decode()

                user = BusinessUser.objects.get(pk=uid)

            except (TypeError, ValueError, OverflowError, BusinessUser.DoesNotExist):

                user = None

            if user is not None and custom_token_generator.check_token(user, token):

                user.is_verified = True

                user.save()

                return get_response_schema({}, get_global_success_messages('VERIFIED_SUCCESSFULLY'), status.HTTP_200_OK)
            
            else:

                return get_response_schema({}, get_global_error_messages('INVALID_LINK'), status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            
            print("E", e)


class SendMailForgotPasswordBusinessUser(GenericAPIView):

    permission_classes = [AllowAny]

    def get_object(self, email):
        
        business_user = BusinessUser.objects.filter(
            email=email
        ).first()

        if business_user is None:
            return None
        
        return business_user
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
            }
        )
    )
    def post(self, request):

        data = request.data

        email = data.get('email')  
        
        business_user = self.get_object(email) 
        
        if business_user is not None:

            send_forgot_password_email_business_user(request, business_user)

            return get_response_schema({}, get_global_success_messages('RECORD_CREATED'), status.HTTP_200_OK,)
            
        return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_400_BAD_REQUEST)

    

class VerifyEmailForgotPasswordAPIView(GenericAPIView):
    
    def get(self, request):

        try:
            uidb64 = request.GET.get('uidb64')

            token = request.GET.get('token')
            
            if not uidb64 or not token:

                return get_response_schema({}, get_global_error_messages('INVALID_LINK'), status.HTTP_400_BAD_REQUEST)
            
            try:

                uid = urlsafe_base64_decode(uidb64).decode()

                user = BusinessUser.objects.get(pk=uid)

            except (TypeError, ValueError, OverflowError, BusinessUser.DoesNotExist):

                user = None

            if user is not None and custom_token_generator.check_token(user, token):

                return get_response_schema({}, get_global_success_messages('VERIFIED_SUCCESSFULLY'), status.HTTP_200_OK)
            
            else:

                return get_response_schema({}, get_global_error_messages('INVALID_LINK'), status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            
            print("E", e)


class ForgotPasswordBusinessUser(GenericAPIView):

    permission_classes = [AllowAny]

    def get_object(self, id):
        
        business_user = BusinessUser.objects.filter(
            id=id
        ).first()

        if business_user is None:
            return None
        
        return business_user
    
    def post(self, request):
        
        data = request.data

        uidb64 = data["uidb64"]

        new_password = data["new_password"]

        uid = urlsafe_base64_decode(uidb64).decode()

        business_user = self.get_object(uid) 

        if business_user is not None:

            business_user.set_password(new_password)

            business_user.save()

            return get_response_schema({}, get_global_success_messages('PASSWORD_UPDATED'), status.HTTP_200_OK,)
            
        return get_response_schema({}, get_global_error_messages('NOT_FOUND'), status.HTTP_400_BAD_REQUEST)


def password_forgot_request(request):
    return render(request, "password_forgot_button.html")

def forgot_password_business_user(request):
    return render(request, "change_password.html")
