import secrets
import base64

from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import RSA
from argon2 import PasswordHasher


# Constants for key generation and encryption
HASH_TRUNCATION_SIZE = 16  # 128 bits
RSA_KEY_SIZE = 2048  # 2048 bits
KEY_SIZE_BYTES = 32  # 256 bits
KEY_SIZE_BITS = 256  # 256 bits
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


def decrypt_data(key, data):
    IV, tag, ciphertext = extract_chacha_cipher_infos(data)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=IV)
    return cipher.decrypt_and_verify(ciphertext, tag)


def stretch_key(entry, salt):
    return HKDF(entry, KEY_SIZE_BYTES, salt, SHA256, context=HKDF_INFO)


def extract_chacha_cipher_infos(cipher):
    IV = cipher[:12]
    tag = cipher[12:28]
    ciphertext = cipher[28:]
    return IV, tag, ciphertext


def generate_rsa_key_pair():
    rsa_key = RSA.generate(RSA_KEY_SIZE)
    public_key = rsa_key.publickey().export_key()
    private_key = rsa_key.export_key()
    return private_key, public_key


def generate_symmetric_key():
    return secrets.randbits(KEY_SIZE_BITS).to_bytes(KEY_SIZE_BYTES, byteorder='big')