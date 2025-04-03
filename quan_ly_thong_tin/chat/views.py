from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from quan_ly_thong_tin.ma_hoa_RSA.rsa import generate_rsa_keys, encrypt, decrypt
from quan_ly_thong_tin.ma_hoa_RSA.oaep import oaep_encode, oaep_decode
import os
import binascii
import json
from quan_ly_thong_tin.file_ma_hoa import ma_hoa, giai_ma

# Create your views here.

def lobby(request):
    return render(request, 'chat/lobby.html')

def user_chat(request):
    return render(request, 'chat/userChat.html')

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def generate_rsa(request):
    try:
        bits = 1024
        public_key, private_key = generate_rsa_keys(bits)
        # Lưu khóa vào session để dùng sau
        request.session['rsa_public_key'] = {'e': str(public_key[0]), 'n': str(public_key[1])}
        request.session['rsa_private_key'] = {'d': str(private_key[0]), 'n': str(private_key[1])}
        return JsonResponse({
            'public_key': f"{public_key[0]},{public_key[1]}",
            'message': 'Đã sinh cặp khóa RSA thành công!'
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def generate_aes(request):
    try:
        aes_key = os.urandom(16)  # Sinh khóa AES-128
        aes_key_hex = binascii.hexlify(aes_key).decode('utf-8')
        # Lưu khóa AES vào session
        request.session['aes_key'] = aes_key_hex
        return JsonResponse({
            'aes_key': aes_key_hex,
            'message': 'Đã sinh khóa AES thành công!'
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def encrypt_aes(request):
    try:
        # Lấy dữ liệu từ request.body và parse JSON
        print("Body nhận được:", request.body)  # Debug dữ liệu thô
        body = request.body.decode('utf-8')  # Chuyển bytes thành string
        data = json.loads(body)  # Parse JSON
        print("Dữ liệu JSON:", data)  # Debug dữ liệu đã parse

        if 'aes_key' not in request.session:
            return JsonResponse({'error': 'Chưa sinh khóa AES! Vui lòng sinh khóa AES trước.'}, status=400)

        public_key_str = data.get('public_key', '').strip()
        if not public_key_str:
            return JsonResponse({'error': 'Vui lòng cung cấp khóa công khai!'}, status=400)

        # Chuyển đổi chuỗi public_key thành tuple (e, n)
        try:
            e, n = map(int, public_key_str.split(','))
            public_key = (e, n)
        except ValueError as ve:
            print("Lỗi định dạng khóa:", ve)
            return JsonResponse({'error': 'Định dạng khóa công khai không hợp lệ! Phải là "e,n"'}, status=400)
        
        aes_key = binascii.unhexlify(request.session['aes_key'])
        
        n_bytes = (public_key[1].bit_length() + 7) // 8
        while True:
            padded_message = oaep_encode(aes_key, n_bytes)
            padded_int = int.from_bytes(padded_message, 'big')
            if padded_int < public_key[1]:
                break
        
        encrypted_aes_key = encrypt(padded_int, public_key)
        encrypted_aes_key_hex = hex(encrypted_aes_key)[2:]
        
        request.session['aes_key'] = encrypted_aes_key_hex
        
        return JsonResponse({
            'encrypted_aes_key': encrypted_aes_key_hex,
            'message': 'Đã mã hóa khóa AES thành công!'
        })
    except json.JSONDecodeError as jde:
        print("Lỗi parse JSON:", jde)
        return JsonResponse({'error': 'Dữ liệu JSON không hợp lệ!'}, status=400)
    except Exception as e:
        print("Lỗi tổng quát:", str(e))
        return JsonResponse({'error': f'Lỗi xử lý: {str(e)}'}, status=500)
    
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def decrypt_aes(request):
    try:
        # Lấy dữ liệu từ request.body và parse JSON
        print("Body nhận được:", request.body)  # Debug
        body = request.body.decode('utf-8')
        data = json.loads(body)
        print("Dữ liệu JSON:", data)  # Debug

        encrypted_aes_hex = data.get('encrypted_aes', '').strip()
        if not encrypted_aes_hex:
            return JsonResponse({'error': 'Vui lòng nhập chuỗi AES đã mã hóa!'}, status=400)

        if 'rsa_private_key' not in request.session:
            return JsonResponse({'error': 'Chưa sinh cặp khóa RSA để lấy khóa bí mật!'}, status=400)

        private_key = (int(request.session['rsa_private_key']['d']), int(request.session['rsa_private_key']['n']))
        n_bytes = (private_key[1].bit_length() + 7) // 8

        # Chuyển chuỗi hex thành số nguyên
        encrypted_aes_int = int(encrypted_aes_hex, 16)
        padded_decrypted_int = decrypt(encrypted_aes_int, private_key)
        padded_decrypted = padded_decrypted_int.to_bytes((padded_decrypted_int.bit_length() + 7) // 8, 'big')
        
        # Đệm thêm byte 0 nếu cần
        if len(padded_decrypted) < n_bytes:
            padded_decrypted = b'\x00' * (n_bytes - len(padded_decrypted)) + padded_decrypted
        
        decrypted_aes_key = oaep_decode(padded_decrypted, n_bytes)
        decrypted_aes_key_hex = binascii.hexlify(decrypted_aes_key).decode('utf-8')
        
        return JsonResponse({
            'decrypted_aes_key': decrypted_aes_key_hex,
            'message': 'Đã giải mã khóa AES thành công!'
        })
    except json.JSONDecodeError as jde:
        print("Lỗi parse JSON:", jde)
        return JsonResponse({'error': 'Dữ liệu JSON không hợp lệ!'}, status=400)
    except ValueError as e:
        print("Lỗi giải mã:", e)
        return JsonResponse({'error': f'Lỗi giải mã: {str(e)}'}, status=400)
    except Exception as e:
        print("Lỗi tổng quát:", str(e))
        return JsonResponse({'error': str(e)}, status=500)
    
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def encrypt_message(request):
    try:
        # Lấy dữ liệu từ request
        body = request.body.decode('utf-8')
        data = json.loads(body)
        message = data.get('message', '').strip()
        aes_key = data.get('aes_key', '').strip()

        if not message or not aes_key:
            return JsonResponse({'error': 'Vui lòng cung cấp tin nhắn và khóa AES!'}, status=400)

        # Mã hóa tin nhắn bằng hàm ma_hoa
        encrypted_message = ma_hoa(message, aes_key)

        return JsonResponse({
            'encrypted_message': encrypted_message,
            'message': 'Đã mã hóa tin nhắn thành công!'
        })
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Dữ liệu JSON không hợp lệ!'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def decrypt_message(request):
    try:
        # Lấy dữ liệu từ request
        body = request.body.decode('utf-8')
        data = json.loads(body)
        encrypted_message = data.get('encrypted_message', '').strip()
        aes_key = data.get('aes_key', '').strip()

        if not encrypted_message or not aes_key:
            return JsonResponse({'error': 'Vui lòng cung cấp tin nhắn mã hóa và khóa AES!'}, status=400)

        # Giải mã tin nhắn bằng hàm giai_ma
        decrypted_message = giai_ma(encrypted_message, aes_key)

        if decrypted_message == "Lỗi giải mã":
            return JsonResponse({'error': 'Không thể giải mã với khóa AES này!'}, status=400)

        return JsonResponse({
            'decrypted_message': decrypted_message,
            'message': 'Đã giải mã tin nhắn thành công!'
        })
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Dữ liệu JSON không hợp lệ!'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)