from django.urls import path
from api import views
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
urlpatterns=[
    path('',views.homeView),
    path('/token/', views.MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('/hello/', views.MyView.as_view(), name='hello'),
    path('/rights/', views.rightsView.as_view(), name='rights'),
    path('/register/', views.RegisterView.as_view(), name='register'),
    #path('/rating/', views.RatingView.as_view(), name='rating'),
    path('/login/', views.LoginView.as_view(), name='login'),
    path('/mobilelogin/', views.MobileView, name='mobilelogin'),
    path('/user/', views.UserView.as_view(), name='user'),
    path('/profile/', views.LoginUserView.as_view(), name='profile'),
    path('/hruser/', views.HrUserView.as_view(), name='hruser'),
    path('/users/', views.UsersView.as_view(), name='users'),
    path('/listusers/', views.userslist, name='listusers'),
    path('/company/', views.Company, name='company'),
    path('/linklogin/', views.LinkLogin, name='linklogin'),
    path('/createuser/', views.createUserView.as_view(), name='createuser'),
    path('/event/', views.EventView.as_view(), name='event'),
    path('/linkbased/', views.LinkBased, name='linkbased'),
    path('/logout/', views.LogoutView.as_view(), name='logout'),
    path('/update/<int:id>', views.UserUpdateView.as_view(), name='update'),

    path('/profile_update/',views.profile_update,name='profile_update'),
    path('/password_change/',views.password_change,name='password_change'),
    path('/registration/',views.Registration, name='registration'),
    path('/new_userinfo/',views.UserInfo, name='new_userinfo'),
    path('/userinfo/',views.new_userinfo,name="userinfo"),
    path('/all_users/',views.all_users,name="all_users"),
    path('/lastlogins/',views.lastlogins,name="lastlogins"),
    path('/activeusers/',views.activeusers,name="activeusers"),
]
