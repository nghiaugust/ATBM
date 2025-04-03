from django.urls import path
from . import views

urlpatterns = [
    path('', views.lobby),
    path('user-chat/', views.user_chat, name='user_chat'),

    path('generate-rsa/', views.generate_rsa, name='generate_rsa'),
    path('generate-aes/', views.generate_aes, name='generate_aes'),
    path('encrypt-aes/', views.encrypt_aes, name='encrypt_aes'),
    path('decrypt-aes/', views.decrypt_aes, name='decrypt_aes'),
    path('encrypt-message/', views.encrypt_message, name='encrypt_message'),
    path('decrypt-message/', views.decrypt_message, name='decrypt_message'),
] 