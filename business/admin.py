from django.contrib import admin
from business.models import (
    BusinessUser,
    Location,
    BusinessImage,
    BusinessSocialMedia,
)


class BusinessUserAdmin(admin.ModelAdmin):
    list_display = ["id", "business_name", "email", "business_user_role",]


class LocationAdmin(admin.ModelAdmin):
    list_display = ["id", "address", "latitude", "longitude",]


class BusinessImageAdmin(admin.ModelAdmin):
    list_display = ["id", "business_name",]

    def business_name(self, obj):
        return obj.business.business_name


class BusinessSocialMediaAdmin(admin.ModelAdmin):
    list_display = ["id", "business_name", "social_media_type",]

    def business_name(self, obj):
        return obj.business.business_name
    

admin.site.register(BusinessUser, BusinessUserAdmin)
admin.site.register(Location, LocationAdmin)
admin.site.register(BusinessImage, BusinessImageAdmin)
admin.site.register(BusinessSocialMedia, BusinessSocialMediaAdmin)
