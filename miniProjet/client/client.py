from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import ChaCha20_Poly1305
import json
import base64
import requests

# Constants for key generation and encryption
HASH_TRUNCATION_SIZE = 16  # 128 bits
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
RSA_KEY_SIZE = 2048
CHA_CHA20_KEY_SIZE = 32  # 256 bits


def hash_username(username):
    return SHA256.new(username.encode()).digest()[:HASH_TRUNCATION_SIZE]


def generate_master_key(master_password, salt):
    return scrypt(master_password.encode(), salt, key_len=32, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)


def encrypt_data(key, data):
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()


def create_account(username, master_password):
    # Step 1-4: Generate master key with username as salt
    salt = hash_username(username)
    master_key = generate_master_key(master_password, salt)

    # Step 5: Generate master password hash
    master_password_hash = generate_master_key(master_password, master_key)

    # Step 6: Generate RSA key pair
    rsa_key = RSA.generate(RSA_KEY_SIZE)
    public_key = rsa_key.publickey().export_key()
    private_key = rsa_key.export_key()

    # Step 7-8: Encrypt the symmetric key and private RSA key
    symmetric_key = get_random_bytes(CHA_CHA20_KEY_SIZE)
    encrypted_symmetric_key = encrypt_data(master_key, symmetric_key)
    encrypted_private_key = encrypt_data(symmetric_key, private_key)

    # Step 9: Prepare data to send to server
    user_data = {
        'username': username,
        'master_password_hash': base64.b64encode(master_password_hash).decode(),
        'encrypted_symmetric_key': encrypted_symmetric_key,
        'public_key': base64.b64encode(public_key).decode(),
        'encrypted_private_key': encrypted_private_key
    }

    return user_data


# Example usage
username = input("Enter your username: ")
master_password = input("Enter your master password: ")

user_data = create_account(username, master_password)

# Send data to the server
response = requests.post('http://localhost:5000/register', json=user_data)

if response.status_code == 200:
    print("Account created successfully.")
else:
    print("An error occurred while creating the account.")


def login(username, master_password):
    # Login logic would be similar to account creation, but instead, we would
    # send a login request to the server with the username and master password hash
    salt = hash_username(username)
    master_password_hash = generate_master_key(master_password, salt)
    login_data = {
        'username': username,
        'master_password_hash': base64.b64encode(master_password_hash).decode()
    }
    response = requests.post('http://localhost:5000/login', json=login_data)
    return response


def change_password(username, old_password, new_password):
    # To change the password, the user must first log in with the old password
    # If login is successful, proceed to update the user's credentials with the new password
    login_response = login(username, old_password)
    if login_response.status_code == 200:
        new_salt = hash_username(username)
        new_master_key = generate_master_key(new_password, new_salt)
        new_master_password_hash = generate_master_key(new_password, new_master_key)
        update_data = {
            'username': username,
            'new_master_password_hash': base64.b64encode(new_master_password_hash).decode()
        }
        response = requests.post('http://localhost:5000/change_password', json=update_data)
        return response
    else:
        return login_response


# Example usage
# For login
login_response = login("username", "master_password")
if login_response.status_code == 200:
    print("Login successful.")
else:
    print("Login failed.")

# For password change
change_password_response = change_password("username", "old_master_password", "new_master_password")
if change_password_response.status_code == 200:
    print("Password changed successfully.")
else:
    print("Password change failed.")
