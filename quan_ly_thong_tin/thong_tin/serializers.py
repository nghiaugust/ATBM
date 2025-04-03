from rest_framework import serializers
from .models import ThongTin 

class ThongTinSerializer(serializers.ModelSerializer):

    class Meta:
        model = ThongTin
        fields = ['id', 'tieu_de', 'du_lieu', 'user']
        extra_kwargs = {'user': {'read_only': True}}  # Không cho phép gửi user_id giúp người dùng ko thể tạo dữ liệu với quyền sử dụng của user khác mà phải là của chính user đang đăng nhập