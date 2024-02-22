import pytest
from django.urls import reverse
from rest_framework import status
import requests_mock
from unittest import mock
from rest_framework.test import APIClient
from mixer.backend.django import mixer
from business.serializers import BusinessUserSerializer
import json
from decimal import Decimal
from django.utils.http import urlsafe_base64_decode
from unittest.mock import patch
from business.models import (
    BusinessUser,
)
from business.views import (
    GetBusinessUserView,
    LogoutBusinessUser,
    SendMailForgotPasswordBusinessUser,
)
from oneheartmarket.utils import  (
    custom_token_generator,
    get_global_success_messages
)


from faker import Faker
faker = Faker()

@pytest.fixture
def mock_api():
    with requests_mock.Mocker() as m:
        yield m


@pytest.fixture
def patch_auth_and_perm(mocker):
    mocker.patch.object(GetBusinessUserView, 'authentication_classes', [])
    mocker.patch.object(GetBusinessUserView, 'permission_classes', [])
    mocker.patch.object(LogoutBusinessUser, 'authentication_classes', [])
    mocker.patch.object(LogoutBusinessUser, 'permission_classes', [])

@pytest.fixture
def business_user_request_data():
    return {
        "business_name": "Dummy",
        "email": faker.email(),
        "password": "Abc@123",
        "business_category": "Computers & Electronics",
        'business_location': {
            'latitude': '123.456',
            'longitude': '789.012',
            'address': '123 Example St'
        }
    }


class TestGetBusinessUserView:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = APIClient()

    @pytest.mark.django_db
    def test_get_existing_business_user(self, mocker, patch_auth_and_perm):

        business_user = mixer.blend(BusinessUser, id=71)

        mocker.patch.object(GetBusinessUserView, 'get_object', return_value=business_user)

        response = self.client.get(reverse('get-business-user', kwargs={'id': business_user.id}))

        serializer = BusinessUserSerializer(instance=business_user)
        expected_data = serializer.data

        assert response.status_code == status.HTTP_200_OK

        assert response.data['results'] == expected_data


    @pytest.mark.django_db
    def test_get_nonexistent_business_user(self, mocker, patch_auth_and_perm):

        mocker.patch.object(GetBusinessUserView, 'get_object', return_value=None)

        response = self.client.get(reverse('get-business-user', kwargs={'id': 99999}))

        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestCreateBusinessUserView:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = APIClient()


    @pytest.mark.django_db
    def test_create_successful_business_user(self, mocker, patch_auth_and_perm, business_user_request_data):
        
        data_json = json.dumps(business_user_request_data)

        response = self.client.post(reverse('create-business-user'), data=data_json,  content_type='application/json')

        assert response.status_code == status.HTTP_201_CREATED

        assert response.data["message"] == "The record was successfully created."
        assert response.data["results"]["business_name"] == business_user_request_data["business_name"]
        assert response.data["results"]["email"] == business_user_request_data["email"]
        assert response.data["results"]["business_category"] == business_user_request_data["business_category"]
        assert response.data["results"]["business_location"]["latitude"] == Decimal(business_user_request_data["business_location"]["latitude"])
        assert response.data["results"]["business_location"]["longitude"] == Decimal(business_user_request_data["business_location"]["longitude"])
        assert response.data["results"]["business_location"]["address"] == business_user_request_data["business_location"]["address"]


    @pytest.mark.django_db
    def test_empty_location_failure_business_User(self, mocker, patch_auth_and_perm, business_user_request_data):

        business_user_request_data["business_location"]["latitude"] = ""

        data_json = json.dumps(business_user_request_data)

        response = self.client.post(reverse('create-business-user'), data=data_json,  content_type='application/json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        assert response.data["message"] == "Bad request."


    @pytest.mark.django_db
    def test_invalid_category_business_User(self, mocker, patch_auth_and_perm, business_user_request_data):

        business_user_request_data["business_category"] = "Wrong Category"

        data_json = json.dumps(business_user_request_data)

        response = self.client.post(reverse('create-business-user'), data=data_json,  content_type='application/json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        assert response.data["message"] == "Bad request."


    @pytest.mark.django_db
    def test_wrong_email_business_User(self, mocker, patch_auth_and_perm, business_user_request_data):

        business_user_request_data["email"] = "Wrong email"

        data_json = json.dumps(business_user_request_data)

        response = self.client.post(reverse('create-business-user'), data=data_json,  content_type='application/json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        assert response.data["message"] == "Bad request."


    @pytest.mark.django_db
    def test_empty_business_name_business_User(self, mocker, patch_auth_and_perm, business_user_request_data):

        business_user_request_data["business_name"] = ""

        data_json = json.dumps(business_user_request_data)

        response = self.client.post(reverse('create-business-user'), data=data_json,  content_type='application/json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        assert response.data["message"] == "Bad request."


    # @pytest.mark.django_db
    # @patch('oneheartmarket.utils.send_verification_email')
    # def test_send_verification_email_failure(self, mock_send_verification_email, mocker, patch_auth_and_perm, business_user_request_data):
    #     # Arrange: Mocking the send_verification_email function to raise an exception
    #     mock_send_verification_email.side_effect = Exception('Failed to send email')

    #     # Act: Make a request to create a business user
    #     data_json = json.dumps(business_user_request_data)
    #     response = self.client.post(reverse('create-business-user'), data=data_json, content_type='application/json')

    #     # Assert: Check that the response indicates failure to send email
    #     assert response.status_code == status.HTTP_400_BAD_REQUEST
    #     assert response.data["message"] == "Bad request."
    #     assert response.data["results"] == "Failed to send email"


class TestBusinessUserLogin:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = APIClient()


    @pytest.mark.django_db
    def test_login_invalid_credentials(self, mocker, patch_auth_and_perm):

        data = {
            "email": "",
            "password": ""
        }

        mocker.patch('business.views.authenticate', return_value=None)

        response = self.client.post(reverse('login-business-user'), data=data)

        assert response.status_code == status.HTTP_404_NOT_FOUND 

        assert response.data["message"] == "Bad request."
        assert response.data["results"] == "User not found."


    @pytest.mark.django_db
    def test_login_check_id_active(self, mocker, patch_auth_and_perm):
        
        user = mixer.blend(BusinessUser, email= "testuser@yopmail.com", password=  "Test@123", is_active = False)

        mocker.patch('business.views.authenticate', return_value=user)

        response = self.client.post(reverse('login-business-user'), data={"email": user.email, "password": user.password,  "is_active": user.is_active })

        assert response.status_code == status.HTTP_403_FORBIDDEN

        assert response.data["message"] == "Bad request."
        assert response.data["results"] == "User is not active."


    @pytest.mark.django_db
    def test_login_check_is_verified(self, mocker, patch_auth_and_perm):

        user = mixer.blend(BusinessUser, email= "testuser@yopmail.com", password=  "Test@123", is_active = True, is_verified = False)

        mocker.patch('business.views.authenticate', return_value=user)

        response = self.client.post(reverse('login-business-user'), data={"email": user.email, "password": user.password,  "is_active": user.is_active, "is_verified": user.is_verified })

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        assert response.data["message"] == "Bad request."
        assert response.data["results"] == "Account is un-verified."


    @pytest.mark.django_db
    def test_login_success(self, mocker, patch_auth_and_perm):

        user = mixer.blend(BusinessUser, email= "testuser@yopmail.com", password=  "Test@123", is_active = True, is_verified = True)

        data = {
            "email": user.email,
            "password": user.password,
            "is_active": user.is_active,
            "is_verified": user.is_verified
        }

        data_json = json.dumps(data)

        mocker.patch('business.views.authenticate', return_value=user)

        response = self.client.post(reverse('login-business-user'), data=data_json,  content_type='application/json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Logged in successfully."
        assert response.data["results"]["email"] == "testuser@yopmail.com"
        assert 'access' in response.data["results"]
        assert 'refresh' in response.data["results"]


class TestBusinessUserLogout:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = APIClient()


    @pytest.mark.django_db
    def test_login_invalid_credentials(self, mocker, patch_auth_and_perm):

        data = {
            "refresh": "",
        }

        mocker.patch('business.views.authenticate', return_value=None)

        response = self.client.post(reverse('logout-business-user'), data=data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST 

        assert response.data["message"] == "Bad request."
        assert response.data["results"] == "Refresh token is invalid or expired. Please try again."


    @pytest.mark.django_db
    def test_logout_business_user_fail(self, mocker, patch_auth_and_perm):

        data = {
            "refresh" : "wrong refresh token"
        }

        response = self.client.post(reverse('logout-business-user'),  data=data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST


    @pytest.mark.django_db
    def test_logout_business_user_success(self, mocker, patch_auth_and_perm):

        mocker.patch('business.views.RefreshToken', autospec=True)
        mocker.patch('business.views.RefreshToken.blacklist', return_value=None)

        data = {
            "refresh" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTcwODUxNTY4NSwiaWF0IjoxNzA4NTA4NDg1LCJqdGkiOiI2YjQwMDMyYjljZjE0MWFkYThjY2FmMWQ1ZTNlMWViZiIsInVzZXJfaWQiOjc2fQ.zdqEYh9hHdi6SgjvuQ9wRxHv26pTLXyBAlAzbBWhmao"
        }

        response = self.client.post(reverse('logout-business-user'),  data=data)

        assert response.status_code == status.HTTP_200_OK


class TestVerifyBusinessUserEmail:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = APIClient()


    @pytest.mark.django_db
    def test_empty_or_none_uid_and_token(self, mocker, patch_auth_and_perm):

        mocker.patch('business.views.BusinessUser.objects.filter')

        data = {
            "uidb64": "",
            "token" : ""
        }
        token = data["token"]
        uidb64 = data["uidb64"]

        url = f"http://127.0.0.1:8000/business-user/verify-email/?uidb64={uidb64}&token={token}"
        response = self.client.get(url)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST


    @pytest.mark.django_db
    def test_valid_uid_and_token(self, mocker):

        mocker.patch('business.views.BusinessUser.objects.filter')

        mocker.patch('business.views.custom_token_generator.check_token', return_value=True)

        data = {
            "uidb64": "Nzk",
            "token" : "c2qx74-257fabc9dcabd010a42abbfe70e8f44e"
        }
        token = data["token"]
        uidb64 = data["uidb64"]

        url = reverse('verify-email')
        response = self.client.get(url, data=data)

        business_user_filter_mock = BusinessUser.objects.filter
        uid_decoded = urlsafe_base64_decode(uidb64).decode()
        business_user_filter_mock.assert_called_once_with(id=uid_decoded)

        custom_token_generator_mock = custom_token_generator.check_token
        custom_token_generator_mock.assert_called_once_with(mock.ANY, token) 
        
        assert response.status_code == status.HTTP_200_OK


    @pytest.mark.django_db
    def test_in_valid_uid_and_token(self, mocker):

        mocker.patch('business.views.BusinessUser.objects.filter')

        mocker.patch('business.views.custom_token_generator.check_token', return_value=False)

        data = {
            "uidb64": "Nzk",
            "token" : "c2qx74-257fabc9dcabd010a42abbfe70e8f44e"
        }
        token = data["token"]
        uidb64 = data["uidb64"]

        url = f"http://127.0.0.1:8000/business-user/verify-email/?uidb64={uidb64}&token={token}"
        response = self.client.get(url)

        assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestSendMailForgotPasswordBusinessUser:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = APIClient()


    @pytest.mark.django_db
    @patch('business.views.send_forgot_password_email_business_user')
    def test_send_mail_success(self, mocker):
        business_user = mixer.blend(BusinessUser, id=71)

        mocker.patch.object(SendMailForgotPasswordBusinessUser, 'get_object', return_value=business_user)

        data = {
            "email": business_user.email,
        }

        mocker.patch('business.views.custom_token_generator.check_token', return_value=True)

        response = self.client.post(reverse('send-mail-forgotpassword-businessuser'), data=data)

        assert response.status_code == status.HTTP_200_OK


    @pytest.mark.django_db
    @patch('business.views.send_forgot_password_email_business_user')
    def test_send_mail_failure_no_user(self, mocker):
        
        mocker.patch.object(SendMailForgotPasswordBusinessUser, 'get_object', return_value=None)

        data = {
            "email": "nonexistent@example.com",
        }

        mocker.patch('business.views.custom_token_generator.check_token', return_value=False)

        response = self.client.post(reverse('send-mail-forgotpassword-businessuser'), data=data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestVerifyEmailForgotPasswordAPIView:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = APIClient()


    @pytest.mark.django_db
    def test_empty_or_none_uid_and_token(self, mocker, patch_auth_and_perm):

        mocker.patch('business.views.BusinessUser.objects.filter')

        data = {
            "uidb64": "",
            "token" : ""
        }
        token = data["token"]
        uidb64 = data["uidb64"]

        url = f"http://127.0.0.1:8000/business-user/Verify-Email-Forgot-Password-businessuser/?uidb64={uidb64}&token={token}"
        response = self.client.get(url)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST


    @pytest.mark.django_db
    def test_valid_uid_and_token(self, mocker):

        mocker.patch('business.views.BusinessUser.objects.filter')

        mocker.patch('business.views.custom_token_generator.check_token', return_value=True)

        data = {
            "uidb64": "Nzk",
            "token" : "c2qx74-257fabc9dcabd010a42abbfe70e8f44e"
        }
        token = data["token"]
        uidb64 = data["uidb64"]

        url = f"http://127.0.0.1:8000/business-user/Verify-Email-Forgot-Password-businessuser/?uidb64={uidb64}&token={token}"
        response = self.client.get(url)

        business_user_filter_mock = BusinessUser.objects.filter
        uid_decoded = urlsafe_base64_decode(uidb64).decode()
        business_user_filter_mock.assert_called_once_with(id=uid_decoded)

        custom_token_generator_mock = custom_token_generator.check_token
        custom_token_generator_mock.assert_called_once_with(mock.ANY, token) 
        
        assert response.status_code == status.HTTP_200_OK


    @pytest.mark.django_db
    def test_in_valid_uid_and_token_forgot_password(self, mocker):

        mocker.patch('business.views.BusinessUser.objects.filter')

        mocker.patch('business.views.custom_token_generator.check_token', return_value=False)

        data = {
            "uidb64": "Nzk",
            "token" : "c2qx74-257fabc9dcabd010a42abbfe70e8f44e"
        }
        token = data["token"]
        uidb64 = data["uidb64"]

        url = f"http://127.0.0.1:8000/business-user/Verify-Email-Forgot-Password-businessuser/?uidb64={uidb64}&token={token}"
        response = self.client.get(url)

        assert response.status_code == status.HTTP_400_BAD_REQUEST


    @pytest.mark.django_db
    def test_valid_uid_and_token_final(self, mocker):
        mocker.patch('business.views.BusinessUser.objects.filter')

        mocker.patch('business.views.custom_token_generator.check_token', return_value=True)

        data = {
            "uidb64": "Nzk",
            "token" : "c2qx74-257fabc9dcabd010a42abbfe70e8f44e"
        }
        token = data["token"]
        uidb64 = data["uidb64"]

        url = f"http://127.0.0.1:8000/business-user/Verify-Email-Forgot-Password-businessuser/?uidb64={uidb64}&token={token}"
        response = self.client.get(url)

        business_user_filter_mock = BusinessUser.objects.filter
        uid_decoded = urlsafe_base64_decode(uidb64).decode()
        business_user_filter_mock.assert_called_once_with(id=uid_decoded)

        custom_token_generator_mock = custom_token_generator.check_token
        custom_token_generator_mock.assert_called_once_with(mock.ANY, token) 
        
        assert response.status_code == status.HTTP_200_OK


class TestForgotPasswordBusinessUser:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = APIClient()


    @pytest.mark.django_db
    @patch('business.views.ForgotPasswordBusinessUser.get_object')
    def test_valid_password_reset(self, mocked_get_object):

        json_data = {
            "uidb64": "NGC",
            "new_password": "valid_password"
        }

        response = self.client.post(reverse('Forgot-Password-businessuser'), data=json_data)

        assert response.status_code == status.HTTP_200_OK


    @pytest.mark.django_db
    @patch('business.views.ForgotPasswordBusinessUser.get_object')
    def test_empty_password_reset(self, mocked_get_object):
        
        json_data = {
            "uidb64": "NGC",
            "new_password": ""
        }

        response = self.client.post(reverse('Forgot-Password-businessuser'), data=json_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST


    @pytest.mark.django_db
    @patch('business.views.ForgotPasswordBusinessUser.get_object')
    def test_invalid_uid_password_reset(self, mocked_get_object):

        def get_object_side_effect(uid):
            if uid is None or uid == "":
                return None
            else:
                return mixer.blend(BusinessUser, id=2)
            
        mocked_get_object.side_effect = get_object_side_effect

        json_data = {
            "uidb64": "",
            "new_password": "valid_password"
        }

        response = self.client.post(reverse('Forgot-Password-businessuser'), data=json_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
