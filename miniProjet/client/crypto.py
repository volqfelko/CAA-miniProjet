from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
from argon2 import PasswordHasher
import base64


# Constants for key generation and encryption
HASH_TRUNCATION_SIZE = 16  # 128 bits
RSA_KEY_SIZE = 2048
CHA_CHA20_KEY_SIZE = 32  # 256 bits
HKDF_INFO = b'client-auth'

# Initialize Argon2 PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=16, encoding='utf-8')


def hash_username(username):
    return SHA256.new(username.encode()).digest()[:HASH_TRUNCATION_SIZE]


def argon2_hash(master_password, salt):
    return ph.hash(master_password, salt=salt)


def encrypt_data(key, data):
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.urlsafe_b64encode(cipher.nonce + tag + ciphertext).decode()


def extract_chacha_cipher_infos(cipher):
    IV = cipher[:12]
    tag = cipher[12:28]
    ciphertext = cipher[28:]

    return IV, tag, ciphertext
