from django.urls import path
from . import views

urlpatterns = [
    path('' , views.Home , name='home'),
    path('signup/' , views.SignupView , name='signup'),
    path('login/' , views.LoginView , name='login'),
    path('logout/' , views.LogoutView , name='logout'),
    path('forgot_password/' , views.ForgotPassword , name='forgot_password'),
    path('password_reset_sent/<str:reset_id>/' , views.PasswordResetSent , name='password_reset_sent'),
    path('reset_password/<str:reset_id>/' , views.ResetPasswordView , name='reset_password'),
    path('chats/' , views.ChatsView , name='chats'),
]
