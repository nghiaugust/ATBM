from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token

# Đăng ký user
class RegisterView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username đã tồn tại'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, password=password)
        token, _ = Token.objects.get_or_create(user=user)  # Tạo token cho user

        return Response({'message': 'Đăng ký thành công', 'token': token.key}, status=status.HTTP_201_CREATED)

# Đăng nhập user
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if user is None:
            return Response({'error': 'Sai tài khoản hoặc mật khẩu'}, status=status.HTTP_401_UNAUTHORIZED)

        token, _ = Token.objects.get_or_create(user=user)
        return Response({'message': 'Đăng nhập thành công', 'token': token.key})

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            request.user.auth_token.delete()  # Xóa token
            return Response({'message': 'Đăng xuất thành công'}, status=status.HTTP_200_OK)
        except:
            return Response({'error': 'Lỗi khi đăng xuất'}, status=status.HTTP_400_BAD_REQUEST)

# Lấy thông tin user (chỉ khi đã đăng nhập)
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({'id': user.id, 'username': user.username, 'email': user.email})

# Cập nhật user
class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        user.email = request.data.get('email', user.email)
        user.save()
        return Response({'message': 'Cập nhật thành công'})

# Xóa user
class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({'message': 'Xóa tài khoản thành công'}, status=status.HTTP_204_NO_CONTENT)

# Lấy danh sách users
class ListUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = User.objects.exclude(id=request.user.id).values('id', 'username')
        return Response(users)
