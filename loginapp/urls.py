from django.contrib.auth import views as auth
from django.urls import path
from loginapp import views
urlpatterns = [
    path('d_login',views.d_login,name="d_login" ),
    path('d_guest',views.d_guest,name="d_guest" ),
    path('dashboard',views.d_success,name="dashboard" ),
    path('d_register',views.d_register,name="d_register" ),
    path('d_validate',views.d_validate,name="d_validate" ),
    path('nw_error',views.lav_nw_error,name="nw_error" ),
    # path('logout/', auth.LogoutView.as_view(template_name ='lav_login.html'), name ='logout'),
]
