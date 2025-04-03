from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('user/', include('user.urls')),
    path('thong_tin/', include('thong_tin.urls')),
    path('chat/', include('chat.urls')),
]
