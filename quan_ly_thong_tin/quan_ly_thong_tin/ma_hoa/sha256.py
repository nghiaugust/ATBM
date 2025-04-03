# sha256.py
class SHA256:
    def __init__(self):
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        # là 8 giá trị băm ban đầu (h0-h7) căn bậc 2 của 8 số nguyên tố đầu tiên, mỗi giá trị 32 bit

        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        # 64 hằng số (k0-k63) căn bậc ba của 64 số nguyên tố đầu tiên

    def _right_rotate(self, x, n):
        return (x >> n) | (x << (32 - n)) & 0xffffffff
    #tạo sự khuyêch tán và các bit phụ thuộc lẫn nhau

    def _process_chunk(self, chunk):
        """Xử lý khối"""
        # chia 512bit thành 16 từ , 1 từ 32 bit
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:(i+1)*4], 'big') 
            #chuyển 4 byte thành số nguyên 32 bit theo thứ tự big-endian (byte cao nhất ở bên trái)
        for i in range(16, 64):
            s0 = self._right_rotate(w[i-15], 7) ^ self._right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = self._right_rotate(w[i-2], 17) ^ self._right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
            #rộng từ 16 thành 64 từ

        #lấy 8 giá trị từ self.h vào biến a, b, c, d, e, f, g, h
        a, b, c, d, e, f, g, h = self.h
        for i in range(64):
            s1 = self._right_rotate(e, 6) ^ self._right_rotate(e, 11) ^ self._right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + s1 + ch + self.k[i] + w[i]) & 0xffffffff
            s0 = self._right_rotate(a, 2) ^ self._right_rotate(a, 13) ^ self._right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xffffffff
            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xffffffff, c, b, a, (temp1 + temp2) & 0xffffffff
# S1: Trộn bit của e bằng xoay và XOR.
# Ch: Hàm "choose" (phi tuyến).
# temp1: Tổng của h, S1, Ch, hằng số k[i], và từ w[i].
# S0: Trộn bit của a.
# Maj: Hàm "majority" (phi tuyến).
# temp2: Tổng của S0 và Maj.
# Cập nhật: Dịch chuyển các biến, cập nhật e và a

        self.h[0] = (self.h[0] + a) & 0xffffffff
        self.h[1] = (self.h[1] + b) & 0xffffffff
        self.h[2] = (self.h[2] + c) & 0xffffffff
        self.h[3] = (self.h[3] + d) & 0xffffffff
        self.h[4] = (self.h[4] + e) & 0xffffffff
        self.h[5] = (self.h[5] + f) & 0xffffffff
        self.h[6] = (self.h[6] + g) & 0xffffffff
        self.h[7] = (self.h[7] + h) & 0xffffffff
# Khuếch tán: S0, S1 trộn bit để một thay đổi nhỏ ở đầu vào ảnh hưởng lớn đến đầu ra.
# Phi tuyến: Ch, Maj làm hàm băm khó đảo ngược.
# Hằng số k[i]: Đảm bảo mỗi vòng khác nhau, tăng tính ngẫu nhiên

    def digest(self, message):
        """Tính SHA-256 của message"""
        msg = bytearray(message)
        orig_len = len(msg) * 8 # độ dài ban đầu tính = bit
        msg.append(0x80) # Thêm bit '1'
        while len(msg) % 64 != 56: # Đệm bằng 0 đến 448 bit modulo 512
            msg.append(0x00)
        msg += orig_len.to_bytes(8, 'big') # Thêm độ dài 64 bit

        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        for i in range(0, len(msg), 64):
            self._process_chunk(msg[i:i+64])
        return b''.join(h.to_bytes(4, 'big') for h in self.h)