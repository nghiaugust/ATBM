# quan_ly_thong_tin/file_ma_hoa.py
from django.conf import settings
from .ma_hoa.hmac import HMACSHA256
from .ma_hoa.fernet_like import CustomFernet
import base64
import os

def pbkdf2_hmac_sha256(password, salt, iterations, length):
    """Triển khai PBKDF2 với HMAC-SHA256 """
    print(f"PBKDF2: Bắt đầu tạo khóa từ mật khẩu, salt={salt.hex()}")
    u = HMACSHA256(password).digest(salt + b'\x00\x00\x00\x01')
    print(f"PBKDF2: Giá trị U ban đầu: {u.hex()}")
    result = bytearray(u)
    for i in range(iterations - 1):
        u = HMACSHA256(password).digest(u)
        if i == 0 or i == iterations - 2:  # Chỉ in đầu và cuối
            print(f"PBKDF2: Vòng lặp {i}, U hiện tại: {u.hex()}")
        for j in range(len(result)):
            result[j] ^= u[j]
    print(f"PBKDF2: Khóa tạo ra: {bytes(result).hex()}")
    return bytes(result[:length])

def generate_key(password: str, salt: bytes = None):
    print(f"generate_key: Bắt đầu tạo khóa từ mật khẩu '{password}'")
    if salt is None:
        salt = settings.SECRET_KEY.encode()[:16]
        print(f"generate_key: Salt mặc định từ SECRET_KEY: {salt.hex()}")
    key = pbkdf2_hmac_sha256(password.encode(), salt, iterations=100, length=32)
    print(f"generate_key: Khóa hoàn tất: {key.hex()}")
    return key

def ma_hoa(value, password):
    print(f"ma_hoa: Bắt đầu mã hóa giá trị '{value}' với mật khẩu '{password}'")
    key = generate_key(password)
    cipher = CustomFernet(key) # mã hoá
    encrypted = cipher.encrypt(value.encode())
    print(f"ma_hoa: Dữ liệu mã hóa (base64): {encrypted.decode()}")
    return encrypted.decode()

def giai_ma(encrypted_value, password):
    print(f"giai_ma: Bắt đầu giải mã giá trị '{encrypted_value}' với mật khẩu '{password}'")
    try:
        key = generate_key(password)
        cipher = CustomFernet(key)
        decrypted = cipher.decrypt(encrypted_value.encode())
        print(f"giai_ma: Dữ liệu giải mã: {decrypted.decode()}")
        return decrypted.decode()
    except Exception as e:
        print(f"giai_ma: Lỗi giải mã: {e}")
        return "Lỗi giải mã"
    
def ma_hoa_chat(value, key):
    key_aes = key.hex()
    cipher = CustomFernet(key_aes) # mã hoá
    encrypted = cipher.encrypt(value.encode())
    print(f"ma_hoa: Dữ liệu mã hóa (base64): {encrypted.decode()}")
    return encrypted.decode()

def giai_ma_chat(encrypted_value, key):
    try:
        key_aes = key.hex()
        cipher = CustomFernet(key_aes)
        decrypted = cipher.decrypt(encrypted_value.encode())
        print(f"giai_ma: Dữ liệu giải mã: {decrypted.decode()}")
        return decrypted.decode()
    except Exception as e:
        print(f"giai_ma: Lỗi giải mã: {e}")
        return "Lỗi giải mã"