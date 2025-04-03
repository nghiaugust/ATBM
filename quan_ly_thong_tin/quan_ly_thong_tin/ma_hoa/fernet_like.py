# quan_ly_thong_tin/ma_hoa/fernet_like.py
from .aes import AES128
from .hmac import HMACSHA256
import os
import time
import base64

class CustomFernet:
    def __init__(self, key=None):
        if key is None:
            self.key = os.urandom(32)
            print(f"CustomFernet: Khóa ngẫu nhiên được tạo: {self.key.hex()}")
        else:
            if len(key) != 32:
                raise ValueError("Khóa phải dài 32 byte")
            self.key = key
            print(f"CustomFernet: Sử dụng khóa từ người dùng: {self.key.hex()}")
        self.enc_key = self.key[:16]
        self.hmac_key = self.key[16:]
        print(f"CustomFernet: Khóa mã hóa AES: {self.enc_key.hex()}")
        print(f"CustomFernet: Khóa HMAC: {self.hmac_key.hex()}")
        self.aes = AES128(self.enc_key)

    def encrypt(self, plaintext, timestamp=None):
        """Sinh vector khởi tạo + timestamp + AES-128 CBC + version + HMAC + base64"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        print(f"encrypt: Dữ liệu gốc: {plaintext}")
        iv = os.urandom(16) # Sinh random vector
        print(f"encrypt: IV ngẫu nhiên: {iv.hex()}")
        if timestamp is None:
            timestamp = int(time.time())
        timestamp_bytes = timestamp.to_bytes(8, 'big') # Dấu thời gian UNIX (8 byte) để kiểm soát thời gian sống của token
        print(f"encrypt: Timestamp: {timestamp} ({timestamp_bytes.hex()})")

        ciphertext = self.aes.encrypt_cbc(plaintext, iv) # mã hoá
        print(f"encrypt: Ciphertext: {ciphertext.hex()}")
        version = b'\x80' #Byte định dạng phiên bản
        data_to_sign = version + timestamp_bytes + iv + ciphertext
        print(f"encrypt: Dữ liệu để ký (version + timestamp + iv + ciphertext): {data_to_sign.hex()}")
        hmac_obj = HMACSHA256(self.hmac_key)
        hmac = hmac_obj.digest(data_to_sign) # Chữ ký số để xác minh tính toàn vẹn + xác thực
        print(f"encrypt: HMAC: {hmac.hex()}")

        token = data_to_sign + hmac 
        print(f"encrypt: Token hoàn chỉnh: {token.hex()}")
        encrypted = base64.urlsafe_b64encode(token) #Chuẩn hóa kết quả đầu ra
        print(f"encrypt: Token mã hóa base64: {encrypted.decode()}")
        return encrypted

    def decrypt(self, token, ttl=None):
        print(f"decrypt: Bắt đầu giải mã token: {token}")
        token = base64.urlsafe_b64decode(token)
        print(f"decrypt: Token sau khi giải base64: {token.hex()}")
        if len(token) < 41:
            raise ValueError("Token không hợp lệ")
        
        version = token[0:1]
        if version != b'\x80':
            raise ValueError("Phiên bản không hợp lệ")
        print(f"decrypt: Version: {version.hex()}")
        
        timestamp_bytes = token[1:9]
        timestamp = int.from_bytes(timestamp_bytes, 'big')
        print(f"decrypt: Timestamp: {timestamp} ({timestamp_bytes.hex()})")
        iv = token[9:25]
        print(f"decrypt: IV: {iv.hex()}")
        ciphertext = token[25:-32]
        print(f"decrypt: Ciphertext: {ciphertext.hex()}")
        received_hmac = token[-32:]
        print(f"decrypt: HMAC nhận được: {received_hmac.hex()}")

        data_to_sign = token[:-32]
        print(f"decrypt: Dữ liệu để kiểm tra HMAC: {data_to_sign.hex()}")
        hmac_obj = HMACSHA256(self.hmac_key)
        computed_hmac = hmac_obj.digest(data_to_sign)
        print(f"decrypt: HMAC tính toán: {computed_hmac.hex()}")
        if computed_hmac != received_hmac:
            raise ValueError("HMAC không khớp")

        if ttl is not None and int(time.time()) - timestamp > ttl:
            raise ValueError("Token hết hạn")
        print(f"decrypt: TTL kiểm tra: {int(time.time()) - timestamp} giây (giới hạn {ttl})")

        plaintext = self.aes.decrypt_cbc(ciphertext, iv)
        print(f"decrypt: Dữ liệu giải mã: {plaintext}")
        return plaintext