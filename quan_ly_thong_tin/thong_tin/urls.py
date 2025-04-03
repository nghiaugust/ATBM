from django.urls import path
from .views import (
    CreateThongTinView,
    UpdateThongTinView,
    ListThongTinView,
    DeleteThongTinView,
    home
)

urlpatterns = [
    path('', home, name='home'),  # Trang chính
    path('create/', CreateThongTinView.as_view(), name='create_thongtin'),
    path('list/', ListThongTinView.as_view(), name='list_thongtin'),
    path('update/<int:pk>/', UpdateThongTinView.as_view(), name='update_thongtin'),
    path('delete/<int:pk>/', DeleteThongTinView.as_view(), name='delete_thongtin'),
]
