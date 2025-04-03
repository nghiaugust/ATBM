from .rsa import generate_rsa_keys, encrypt, decrypt
from .oaep import oaep_encode, oaep_decode
import os

def main():
    try:
        # Sinh cặp khóa RSA
        bits = 1024
        public_key, private_key = generate_rsa_keys(bits)
        print("Khóa công khai RSA (e, n):", public_key)
        print("Khóa bí mật RSA (d, n):", (private_key[0], public_key[1]))

        # Sinh khóa AES-128
        aes_key = os.urandom(16)
        print("Khóa AES-128 (hex):", aes_key.hex())

        # Mã hóa khóa AES bằng RSA với OAEP
        n_bytes = (public_key[1].bit_length() + 7) // 8  # Tính n_bytes từ n

        # Lặp lại encode cho đến khi đảm bảo < n
        while True:
            padded_message = oaep_encode(aes_key, n_bytes)
            padded_int = int.from_bytes(padded_message, 'big')
            if padded_int < public_key[1]:
                break

        print("Padded AES key (bytes, hex):", padded_message.hex()[:10], "...")
        print("Byte đầu của padded AES key:", padded_message[0])

        encrypted_aes_key = encrypt(padded_int, public_key)
        print("Khóa AES mã hóa bằng RSA (ciphertext):", encrypted_aes_key)

        # Giải mã khóa AES
        padded_decrypted_int = decrypt(encrypted_aes_key, private_key)
        padded_decrypted = padded_decrypted_int.to_bytes((padded_decrypted_int.bit_length() + 7) // 8, 'big')
        if len(padded_decrypted) < n_bytes:
            padded_decrypted = b'\x00' * (n_bytes - len(padded_decrypted)) + padded_decrypted
        print("Padded AES key (sau giải mã RSA, bytes, hex):", padded_decrypted.hex()[:10], "...")

        decrypted_aes_key = oaep_decode(padded_decrypted, n_bytes)
        print("Khóa AES giải mã (hex):", decrypted_aes_key.hex())

        # So sánh kết quả
        if decrypted_aes_key == aes_key:
            print("✅ Giải thành công!")
        else:
            print("❌ Giải thất bại!")

    except ValueError as e:
        print(f"Lỗi: {e}")
    except Exception as e:
        print(f"Lỗi không xác định: {e}")

if __name__ == "__main__":
    main()
