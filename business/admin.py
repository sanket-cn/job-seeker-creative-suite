from django.contrib import admin
from business.models import (
    BusinessUser,
    Location,
    BusinessImage,
    BusinessSocialMedia,
)


class BusinessUserAdmin(admin.ModelAdmin):
    list_display = ["id", "business_name", "email", "business_user_role",]

    def get_fieldsets(self, request, obj=None):

        if obj.is_superuser == True and request.user.is_superuser == True:

            return (
                (None, {'fields': ('email', 'password')}),
                ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_verified', 'groups', 'user_permissions')}),
                ('Important dates', {'fields': ('last_login', )}),
            )
        
        else:
            
            return super().get_fieldsets(request, obj)
        
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
