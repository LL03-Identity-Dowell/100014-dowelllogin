from django.contrib.auth import views as auth
from django.urls import path
# from django.contrib import admin
from lavapp import views

# urlpatterns=[
#     path('admin/', admin.site.urls),
# ]
urlpatterns=[
    path('home',views.home,name="home" ),
    path('linkcheck',views.directlinktest,name="linkcheck" ),
    path('facecheck',views.FaceCheck,name="facecheck" ),
    path('lang',views.selectLanguage,name="lang"),
    path('lang1',views.selectLanguage1,name="lang1"),
    path('direct',views.directLink,name="direct"),
    # path('guest',views.GuestPage,name="guest" ),
    # path('otpverify',views.GuestVerify,name="otpverify" ),
    path('register',views.RegisterPage,name="register"),
    path('',views.LoginPage,name="login"),
    path('loginid',views.LoginWithFace,name="loginid"),
    path('main',views.MainPage,name="main"),
    path('createusers',views.CreateUsersPage,name="createusers"),
    path('nwerror',views.NwError,name="nwerror" ),
    path('syserror',views.SysError,name="syserror" ),
    path('accerror',views.AccountError,name="accerror"),
    # path('logout/', auth.LogoutView.as_view(template_name ='login'), name ='logout'),
    path('logout/',views.LogoutView,name="logout"),
    path('l',views.CheckPage,name="l"),
    path('cpusers',views.CopyUsers,name="cpusers"),
    path('land',views.LandPage,name="land"),
    path('bookshow',views.BookShow,name="bookshow"),
    path('simplelogin',views.SimpleLoginPage,name="simplelogin"),
    path('createuser',views.CreateUser),
    # path('test',views.test_login),
    path('testlogin',views.testlogin),
    path('linklogin',views.LinkLogin,name="linklogin"),
    path('linkbased',views.LinkBased,name="linkbased" ),
    # For new designs
    path('update_qrobj',views.update_qrobj,name="update_qrobj"),
    path('qr_creation',views.qr_creation,name="qr_creation"),
    path('redirect_url',views.redirect_url,name="redirect_url"),
    path('forgot_password',views.forgot_password,name="forgot_password"),
    path('forgot_username',views.forgot_username,name="forgot_username"),
    path('change_password',views.change_password,name="change_password"),
    path('allow_location',views.allow_location,name="allow_location"),
    path('sign-out',views.signout, name="sign-out"),
    path('design_login',views.design_login,name="design_login"),
    path('registertest',views.Registertest,name="registertest"),
    path("legalpolicy1",views.LegalP,name="legalpolicy1"),
    path("legalpolicy",views.Policy,name="legalpolicy"),
    path("check_status",views.check_status,name="check_status"),
    path("mobileotp",views.mobileotp,name="mobileotp"),
    path("live_status",views.live_status,name="live_status"),
    path("live_qr_status",views.live_qr_status,name="live_qr_status"),
    path("live_public_status",views.live_public_status,name="live_public_status"),
    path("userdetails",views.userdetails,name="userdetails"),
    path("add_public",views.add_public,name="add_public"),

]
