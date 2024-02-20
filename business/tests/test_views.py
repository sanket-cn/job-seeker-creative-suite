import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from mixer.backend.django import mixer
from business.models import BusinessUser
from business.serializers import BusinessUserSerializer
from rest_framework import status
import pytest
import requests_mock
from business.views import (
    GetBusinessUserView,
)
from django.contrib.auth import (

    authenticate
)

@pytest.fixture
def mock_api():
    with requests_mock.Mocker() as m:
        yield m


@pytest.fixture
def patch_auth_and_perm(mocker):
    mocker.patch.object(GetBusinessUserView, 'authentication_classes', [])
    mocker.patch.object(GetBusinessUserView, 'permission_classes', [])


class TestGetBusinessUserView:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = APIClient()

    @pytest.mark.django_db
    def test_get_existing_business_user(self, mocker, patch_auth_and_perm):

        business_user = mixer.blend(BusinessUser, id=71)

        mocker.patch.object(GetBusinessUserView, 'get_object', return_value=business_user)

        response = self.client.get(reverse('get-business-user', kwargs={'id': business_user.id}))

        assert response.status_code == status.HTTP_200_OK

        serializer = BusinessUserSerializer(instance=business_user)
        expected_data = serializer.data

        assert response.data['results'] == expected_data

    @pytest.mark.django_db
    def test_get_nonexistent_business_user(self, mocker, patch_auth_and_perm):

        mocker.patch.object(GetBusinessUserView, 'get_object', return_value=None)

        response = self.client.get(reverse('get-business-user', kwargs={'id': 99999}))

        assert response.status_code == status.HTTP_404_NOT_FOUND


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
    def test_login_valid_credentials(self, mocker, patch_auth_and_perm):
        user = mixer.blend(BusinessUser, email="sanket.dev025@gmail.com", password="Admin@123", id=71)

        data = {
            "email": "sanket.dev025@gmail.com",
            "password": "Admin@123"
        }

        mocker.patch('business.views.authenticate', return_value=user)

        response = self.client.post(reverse('login-business-user'), data=data)
        print('➡ oneheartmarket/business/tests/test_views.py:111 response:', response)
        print('➡ oneheartmarket/business/tests/test_views.py:111 response:', response.data)
        print('➡ oneheartmarket/business/tests/test_views.py:111 response:', response.data["refresh"])

        assert response.status_code == 200

        assert response.data["message"] == "Logged in successfully."
        assert "refresh" in response.data
        assert "access" in response.data
        