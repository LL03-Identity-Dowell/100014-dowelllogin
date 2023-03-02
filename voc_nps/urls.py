from django.urls import path
from voc_nps import views

urlpatterns=[
    path('',views.index),
    path('home',views.home),
    path('preview',views.preview),
    path('brandurl',views.preview1),
    path('emcode',views.emcode),
    path('qrcode',views.qrGen),
    path('showqrcode',views.ShowQr),
    path('sendqr',views.SendMail),
    path('showvideo',views.ShowVideo),
    path('sendfeed',views.sendfeed),
    path('iframe',views.iframesend),
    path('scale',views.scale),
    path('sendscale',views.sendscale),
    path('dowellscale/<str:tname>',views.dowell_scale),
    path('scaleadmin',views.dowell_scale_admin),
    path('checksession',views.checksession),
    path('getcookie',views.getcookie),
    path('cookie',views.cookie),




]