# Package imports
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, 
    PermissionsMixin
)
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinLengthValidator
import uuid
import os
from django.contrib.auth.models import BaseUserManager
from django_cleanup import cleanup
from django.contrib.auth import get_user_model
from django.utils import timezone

def logo_image_path(instance, filename):

    ext = filename.split('.')[-1]

    filename = f'{uuid.uuid4()}.{ext}'

    return os.path.join('uploads/business_logo/', filename)


def business_image_path(instance, filename):

    ext = filename.split('.')[-1]

    filename = f'{uuid.uuid4()}.{ext}'

    return os.path.join('uploads/business_image/', filename)


class UserManager(BaseUserManager):

    def create_user(self, email, password, business_name, **extra_fields):

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


    def create_superuser(self, email, password, business_name):

        user = self.create_user(
            email=email,
            password=password,
            business_name=business_name,
        )
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user
    

class Location(models.Model):

    latitude = models.DecimalField(max_digits=22, decimal_places=16)
    longitude = models.DecimalField(max_digits=22, decimal_places=16)
    address = models.TextField()

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self. address
    
    
@cleanup.select
class BusinessUser(AbstractBaseUser, PermissionsMixin):

    class CategoriesType(models.TextChoices):
        AUTOMOTIVE_TYPE = 'Automotive', _('Automotive')
        COMPUTER_ELECTRONICS_TYPE = 'Computers & Electronics', _('Computers & Electronics')
        FOOD_DINING_TYPE = 'Food & Dining', _('Food & Dining')

    class RoleType(models.TextChoices):
        SUPERADMIN = 'SuperAdmin', _('SuperAdmin')
        JOBSEEKER = 'Jobseeker', _('Jobseeker')
        RECRUITER = 'Recruiter', _('Recruiter')
        BUSINESSUSER = 'BusinessUser', _('BusinessUser')
        ADVERTISER = 'Advertiser', _('Advertiser')

    business_location = models.ForeignKey(
        'Location', 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='business_user',  
        related_query_name='business_users' 
    )
    
    business_name = models.CharField(max_length = 50)
    email = models.EmailField(max_length=255, unique=True)
    
    logo = models.ImageField(upload_to=logo_image_path, null=True, blank=True)
    overview = models.TextField(max_length=300, null= True, blank= True)
    detailed_description = models.TextField(max_length=300, null= True, blank= True)
    contact_number = models.CharField(validators=[MinLengthValidator(10)], max_length=10, null= True, blank= True)
    awards_name = models.TextField(max_length = 500, null= True, blank= True)

    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)

    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    business_category = models.CharField(choices=CategoriesType.choices, max_length=50)
    business_user_role = models.CharField(choices=RoleType.choices, max_length=50)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    
    REQUIRED_FIELDS = ['business_name', 'business_category', 'business_user_role']

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)  

    def __str__(self):
        return self.email


@cleanup.select
class BusinessImage(models.Model):

    business = models.ForeignKey(
        'BusinessUser', 
        on_delete=models.CASCADE, 
        related_name='business_images',
        related_query_name='business_image'
    )

    image = models.ImageField(upload_to=business_image_path, null=True)

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.business.business_name


class BusinessSocialMedia(models.Model):

    class SocialMediaType(models.TextChoices):
        INSTAGRAM = 'Instagram', _('Instagram')
        FACEBOOK = 'Facebook', _('Facebook')
        TWITTER = 'Twitter', _('Twitter')
    
    business = models.ForeignKey(
        'BusinessUser', 
        on_delete=models.CASCADE, 
        related_name='business_social_medias',
        related_query_name='business_social_media'
    )
    social_media_type = models.CharField(choices=SocialMediaType.choices, max_length=50)
    social_media_link = models.CharField(max_length=50)

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.social_media_type

class AuthToken(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    expiry_time = models.DateTimeField()

    def is_valid(self):
        return self.expiry_time > timezone.now()
    