from django.urls import path
from .views import RegisterView, LoginView, UserProfileView, UpdateUserView, DeleteUserView, LogoutView, ListUsersView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('update/', UpdateUserView.as_view(), name='update'),
    path('delete/', DeleteUserView.as_view(), name='delete'),
    path('list/', ListUsersView.as_view(), name='list_users'),
]
