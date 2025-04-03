from rest_framework import generics, permissions
from rest_framework.response import Response
from .models import ThongTin
from .serializers import ThongTinSerializer
from quan_ly_thong_tin.file_ma_hoa import ma_hoa, giai_ma
from django.shortcuts import render

# Tạo thông tin mới
class CreateThongTinView(generics.CreateAPIView):
    queryset = ThongTin.objects.all()
    serializer_class = ThongTinSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        password = self.request.data.get("password")  # Lấy password từ request
        if not password:
            return Response({"error": "Vui lòng nhập mật khẩu"}, status=400)

        du_lieu = self.request.data.get("du_lieu", "")
        encrypted_data = ma_hoa(du_lieu, password)  # Mã hóa dữ liệu

        serializer.save(user=self.request.user, du_lieu=encrypted_data)  # Lưu vào DB

# Cập nhật thông tin
class UpdateThongTinView(generics.UpdateAPIView):
    queryset = ThongTin.objects.all()
    serializer_class = ThongTinSerializer
    permission_classes = [permissions.IsAuthenticated]

    def update(self, request, *args, **kwargs):
        password = request.data.get("password")  # Lấy password từ request
        if not password:
            return Response({"error": "Vui lòng nhập mật khẩu"}, status=400)

        instance = self.get_object()
        du_lieu_moi = request.data.get("du_lieu", instance.du_lieu)  # Lấy dữ liệu mới
        encrypted_data = ma_hoa(du_lieu_moi, password)  # Mã hóa

        instance.du_lieu = encrypted_data  # Cập nhật dữ liệu
        instance.save()
        
        return Response({"message": "Cập nhật thành công"})

class ListThongTinView(generics.GenericAPIView):
    """Lấy danh sách thông tin, không yêu cầu đăng nhập nhưng giải mã nếu có token + password"""
    serializer_class = ThongTinSerializer
    permission_classes = [permissions.AllowAny]  # Cho phép truy cập không cần đăng nhập

    def post(self, request, *args, **kwargs):
        password = request.data.get("password")  # Lấy mật khẩu từ JSON body
        token = request.auth  # Kiểm tra token trong request

        if token:
            # Nếu có token, lấy dữ liệu của user đang đăng nhập
            queryset = ThongTin.objects.filter(user=request.user)
        else:
            # Nếu không có token, lấy tất cả dữ liệu
            queryset = ThongTin.objects.all()

        data = []
        for item in queryset:
            if password:
                try:
                    decrypted_data = giai_ma(item.du_lieu, password)  # Giải mã nếu có mật khẩu
                except Exception:
                    decrypted_data = "Lỗi giải mã"
            else:
                decrypted_data = item.du_lieu  # Giữ nguyên nếu không có mật khẩu

            data.append({
                "id": item.id,
                "tieu_de": item.tieu_de,
                "du_lieu": decrypted_data,
                "user": item.user.username
            })

        return Response(data, status=200)
    
# Xóa thông tin
class DeleteThongTinView(generics.DestroyAPIView):
    queryset = ThongTin.objects.all()
    serializer_class = ThongTinSerializer
    permission_classes = [permissions.IsAuthenticated]

def home(request):
    return render(request, 'thong_tin/index.html')