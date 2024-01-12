from Crypto.Hash import SHA3_256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import ChaCha20_Poly1305
from argon2 import PasswordHasher
ph = PasswordHasher()

class AccountCreation:
    def __init__(self):
        pass

    def hash_username(self, username):
        # Hash the username and truncate to 128 bits
        return SHA3_256.new(username.encode()).digest()[:16]

    def derive_master_key(self, password, salt):
        # Derive the master key using Argon2id with the provided salt
        return ph.hash(password.encode(), salt=salt, length=16)

    def stretch_key(self, key):
        # Use HKDF to stretch the master key to 256 bits
        return HKDF(key, 32, b'', SHA3_256)

    def generate_symmetric_key(self):
        # Generate a symmetric key using CSPRNG
        return get_random_bytes(32)

    def generate_rsa_key_pair(self):
        # Generate an RSA key pair
        return RSA.generate(2048)

    def encrypt_with_chacha20_poly1305(self, key, data):
        # Encrypt data using ChaCha20-Poly1305
        cipher = ChaCha20_Poly1305.new(key=key)
        cipher.update(b'')  # Associated data is empty
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, cipher.nonce, tag

    def create_account(self, username, master_password):
        username_hash = self.hash_username(username)
        master_key = self.derive_master_key(master_password, username_hash)
        stretched_master_key = self.stretch_key(master_key)
        symmetric_key = self.generate_symmetric_key()
        rsa_key_pair = self.generate_rsa_key_pair()
        protected_symmetric_key, iv_symmetric, tag_symmetric = self.encrypt_with_chacha20_poly1305(stretched_master_key,
                                                                                                   symmetric_key)
        protected_private_key, iv_private, tag_private = self.encrypt_with_chacha20_poly1305(symmetric_key,
                                                                                             rsa_key_pair.export_key())
        master_password_hash = self.derive_master_key(master_password, master_key)

        # Here you would store the credentials including the username, master_password_hash,
        # protected_symmetric_key, protected_private_key, and the IVs and tags for decryption.
        # In a real application, this data should be stored securely in a database or a secure storage mechanism.

        # The following is a placeholder for the storage mechanism:
        storage = {
            "username": username,
            "master_password_hash": master_password_hash,
            "protected_symmetric_key": protected_symmetric_key,
            "iv_symmetric": iv_symmetric,
            "tag_symmetric": tag_symmetric,
            "protected_private_key": protected_private_key,
            "iv_private": iv_private,
            "tag_private": tag_private
        }
        return storage