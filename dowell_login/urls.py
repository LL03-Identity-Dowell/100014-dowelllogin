"""dowell_login URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path,include, re_path
from django.conf.urls.i18n import i18n_patterns
from django.views.generic import TemplateView
from lavapp import views as main
from newlogin import views as old

urlpatterns = [
    path('i18n/',include('django.conf.urls.i18n')),
    path('admin/', admin.site.urls),
    path('loginapp',include('loginapp.urls')),
    #path('nps/',include('voc_nps.urls')),
    path('api',include('api.urls')),
    # path('', include('django_sso.sso_gateway.urls')),
    #path('',include('lavapp.urls')),
    path('linklogin',main.master_login,name="linklogin"),
    path('linkbased',main.LinkBased,name="linkbased" ),
    path('allow_location',main.allow_location,name="allow_location"),
    path("check_status",main.check_status,name="check_status"),
    path("live_status/",main.live_status,name="live_status"),
    path("add_public",main.add_public,name="add_public"),
    path("userdetails",main.userdetails,name="userdetails"),
    path("mobile_register",main.RegisterPage,name="mobile_register"),
    path("main_signout",main.LogoutView,name="main_signout"),
    path("old_login",old.LoginView,name="old"),
    path("removeaccount",main.removeaccount,name="removeaccount"),
    path("legalpolicy1",main.LegalP,name="legalpolicy1"),
    path('',TemplateView.as_view(template_name="index.html")),
    re_path(r'^(?:.*)/?$', TemplateView.as_view(template_name="index.html")),

]+ static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += i18n_patterns(
    #path('',include('loginapp.urls')),
    path('login',include('newlogin.urls')),
    path('beta',include('lavapp.urls')),
    # prefix_default_language=False,
    )

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
