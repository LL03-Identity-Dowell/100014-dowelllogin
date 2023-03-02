from django.contrib.auth import views as auth
from django.urls import path
from newlogin import views
urlpatterns=[
path('',views.HomeView,name="dashboard" ),
path('/linkbased',views.LinkBased,name="linkbased" ),
path('/guest',views.GuestView,name="guest" ),
path('/guestverify',views.GuestVerify,name="guestverify" ),
path('/register',views.RegisterView,name="register" ),
path('/otpverifyuser',views.RegisterVerify,name="otpverifyuser"),
path('/login',views.LoginView,name="login" ),
path('/logout',views.LogoutView,name="logout" ),
path('/loginid',views.LoginWithFace,name="loginid"),
path('/embed',views.embed, name="embed"),
path('/forgot_password',views.forgot_password,name="forgot_password"),
path('/change_password',views.change_password,name="change_password"),
path('/iframe_check',views.iframe,name="iframe"),
path('/sign-out',views.signout,name="sign-out"),
]