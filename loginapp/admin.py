from django.contrib import admin

from django.contrib.auth.admin import UserAdmin

from .models import Account
from .models import GuestAccount, mobile_sms, RandomSession, Linkbased_RandomSession, Location_check, products, Face_Login
class CustomUserAdmin(UserAdmin):
    list_display = (
        'username', 'email', 'first_name', 'last_name', 'is_staff',
        'role', 'profile_image', 'teamcode','phone'
        )

    fieldsets = (
        (None, {
            'fields': ('username', 'password')
        }),
        ('Personal info', {
            'fields': ('first_name', 'last_name', 'email')
        }),
        ('Permissions', {
            'fields': (
                'is_active', 'is_staff', 'is_superuser',
                'groups', 'user_permissions'
                )
        }),
        ('Important dates', {
            'fields': ('last_login', 'date_joined')
        }),
        ('Additional info', {
            'fields': ('role', 'profile_image', 'teamcode','phone')
        })
    )

    add_fieldsets = (
        (None, {
            'fields': ('username', 'password1', 'password2')
        }),
        ('Personal info', {
            'fields': ('first_name', 'last_name', 'email')
        }),
        ('Permissions', {
            'fields': (
                'is_active', 'is_staff', 'is_superuser',
                'groups', 'user_permissions'
                )
        }),
        ('Important dates', {
            'fields': ('last_login', 'date_joined')
        }),
        ('Additional info', {
            'fields': ('role', 'profile_image', 'teamcode','phone')
        })
    )
    ordering = ('date_joined', )
class mobile_smsAdmin(admin.ModelAdmin):
    list_display=('phone', 'username', 'sms', 'expiry')
    search_fields=['phone']

class RandomSessionAdmin(admin.ModelAdmin):
    list_display=('sessionID', 'username', 'status', 'added')
    search_fields=['username','sessionID']

admin.site.register(Account, CustomUserAdmin)
admin.site.register(GuestAccount)
admin.site.register(mobile_sms,mobile_smsAdmin)
admin.site.register(RandomSession,RandomSessionAdmin)
admin.site.register(Linkbased_RandomSession)
admin.site.register(Location_check)
admin.site.register(products)
admin.site.register(Face_Login)