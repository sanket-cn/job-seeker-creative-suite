from django import forms
from business.models import BusinessUser
from django.contrib.auth.forms import UserCreationForm

class SignUpForm(UserCreationForm):

    class Meta(UserCreationForm.Meta):
        model = BusinessUser
        fields = ['email',]


    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.is_verified = True
        user.business_user_role = BusinessUser.RoleType.SUPERADMIN
        if commit:
            user.save()
        return user
    