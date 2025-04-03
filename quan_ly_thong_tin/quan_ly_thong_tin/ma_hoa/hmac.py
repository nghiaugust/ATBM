# quan_ly_thong_tin/ma_hoa/hmac.py
from .sha256 import SHA256

class HMACSHA256:
    def __init__(self, key):
        self.block_size = 64
        # Chỉ in lần đầu tiên để tránh lặp lại
        if not hasattr(self, 'init_logged'):
            print(f"HMACSHA256: Khởi tạo với khóa: {key.hex()}")
        if len(key) > self.block_size:
            key = SHA256().digest(key)[:self.block_size]
            print(f"HMACSHA256: Khóa dài, rút gọn: {key.hex()}")
        if len(key) < self.block_size:
            key += b'\x00' * (self.block_size - len(key))
            if not hasattr(self, 'init_logged'):
                print(f"HMACSHA256: Khóa ngắn, đệm: {key.hex()}")
        self.key = key
        self.ipad = bytes(x ^ 0x36 for x in key) # Mỗi byte của khóa được XOR 0x36
        self.opad = bytes(x ^ 0x5c for x in key) # Mỗi byte của khóa được XOR 0x5c
        #để tạo ra 2 khoá khác nhau, dùng cho 2 lớp băm độc lập
        if not hasattr(self, 'init_logged'):
            print(f"HMACSHA256: ipad: {self.ipad.hex()}")
            print(f"HMACSHA256: opad: {self.opad.hex()}")
            self.init_logged = True

    def digest(self, message):
        """Tính HMAC-SHA256"""
        # Chỉ in lần đầu tiên
        if not hasattr(self, 'digest_count'):
            print(f"HMACSHA256 digest: Bắt đầu tính HMAC cho message: {message.hex()}")
            self.digest_count = 1
        inner = SHA256().digest(self.ipad + message) 
        #băm ipad và message: tạo ràng buộc giữa khoá và thông điệp
        if self.digest_count == 1:
            print(f"HMACSHA256 digest: Inner hash: {inner.hex()}")
        outer = SHA256().digest(self.opad + inner)
        # băm inner và opad
        if self.digest_count == 1:
            print(f"HMACSHA256 digest: Outer hash (HMAC): {outer.hex()}")
            self.digest_count += 1
        return outer