from django.contrib import admin
from django.contrib.sessions.models import Session
from loginapp.models import CustomSession, QR_Creation
admin.site.register(Session)
admin.site.register(CustomSession)
admin.site.register(QR_Creation)
# class SessionAdmin(ModelAdmin):
#     def _session_data(self, obj):
#         return obj.get_decoded()
#     list_display = ['session_key', '_session_data', 'expire_date']
# admin.site.register(Session, SessionAdmin)
admin.site.site_header = 'Dowell administration'
admin.site.site_title  =  "Dowell Admin"
admin.site.index_title  =  "Dowell Users and Tables"