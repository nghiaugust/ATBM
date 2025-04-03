import os
from .sha256 import sha256

def mgf1(seed, length):
    output = b""
    counter = 0
    while len(output) < length:
        c = counter.to_bytes(4, 'big')
        output += sha256(seed + c)
        counter += 1
    return output[:length]

def oaep_encode(message, n_bytes, k0=32, k1=32):
    m_len = len(message)
    if m_len > n_bytes - k0 - k1 - 2:
        raise ValueError(f"Bản rõ quá dài! Tối đa {n_bytes - k0 - k1 - 2} byte, nhận {m_len} byte")

    seed = os.urandom(k0)
    l_hash = sha256(b"")

    ps_len = n_bytes - k0 - k1 - m_len - 2  # ✅ đúng chuẩn
    ps = b"\x00" * ps_len
    db = l_hash + ps + b"\x01" + message

    db_mask = mgf1(seed, len(db))
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    seed_mask = mgf1(masked_db, k0)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    padded_message = b"\x00" + masked_seed + masked_db

    # ✅ Kiểm tra cuối cùng
    if len(padded_message) != n_bytes:
        raise ValueError(f"Độ dài padded_message không đúng: {len(padded_message)} thay vì {n_bytes}")
    if padded_message[0] != 0x00:
        raise ValueError(f"Byte đầu không đúng! padded_message[0] = {padded_message[0]}")

    return padded_message

def oaep_decode(padded_message, n_bytes, k0=32, k1=32):
    if len(padded_message) != n_bytes or padded_message[0] != 0:
        raise ValueError(f"Dữ liệu giải mã không hợp lệ! Độ dài: {len(padded_message)}, byte đầu: {padded_message[0]}")

    masked_seed = padded_message[1:k0+1]
    masked_db = padded_message[k0+1:]

    seed_mask = mgf1(masked_db, k0)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, len(masked_db))
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    l_hash = sha256(b"")
    if db[:k1] != l_hash:
        raise ValueError("lHash không khớp!")

    i = k1
    while i < len(db) and db[i] == 0:
        i += 1
    if i >= len(db) or db[i] != 1:
        raise ValueError("Không tìm thấy byte 0x01!")

    return db[i+1:]
