from rest_framework import serializers
from .models import (
    BusinessUser,
    BusinessImage,
    BusinessSocialMedia,
    Location
)


class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = ['latitude', 'longitude', 'address']


class BusinessSocialMediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessSocialMedia
        fields = '__all__'


class BusinessImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessImage
        fields = '__all__'


class BusinessUserSerializer(serializers.ModelSerializer):
    business_location = LocationSerializer()
    business_social_medias = BusinessSocialMediaSerializer(many=True)
    business_images = BusinessImageSerializer(many=True)

    class Meta:
        model = BusinessUser
        fields = ['email', 'business_name', 'overview', 'detailed_description', 'contact_number', 'awards_name', 'business_category', 'business_user_role', 'created', 'modified', 'is_active', 'is_verified', 'is_superuser', 'is_staff', 'business_location', 'business_social_medias', 'business_images' ]


class CreateBusinessUserSerializer(serializers.ModelSerializer):
    business_location = LocationSerializer()

    class Meta:
        model = BusinessUser
        fields = ['email', 'business_name', 'business_location', 'business_user_role',  'business_category', 'password']


    def to_representation(self, instance):

        data = super().to_representation(instance)

        data.pop('password', None)

        return data
    

    def create(self, validated_data):
        
        password = validated_data.pop('password')

        business_location = validated_data.pop('business_location')

        business_user = BusinessUser(**validated_data)

        business_user.set_password(password)

        create_location = Location.objects.create(**business_location)

        business_user.business_location = create_location
        
        business_user.save()

        return business_user
