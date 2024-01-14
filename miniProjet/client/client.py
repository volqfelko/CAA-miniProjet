import requests
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import ChaCha20_Poly1305
from argon2 import PasswordHasher

import base64

from client.index import ClientIndex

# Constants for key generation and encryption
HASH_TRUNCATION_SIZE = 16  # 128 bits
RSA_KEY_SIZE = 2048
CHA_CHA20_KEY_SIZE = 32  # 256 bits
HKDF_INFO = b'client-auth'

client_index = ClientIndex(None, None)

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


def create_account(username, master_password):
    # Step 1-4: Generate master key with username as salt
    salt = hash_username(username)
    master_key = argon2_hash(master_password, salt).encode('utf-8')[-16:]

    # Step 5: Generate master password hash
    master_password_hash = argon2_hash(master_password, master_key).encode('utf-8')[-16:]

    #TODO salt HKDF ????
    stretched_master_key = HKDF(master_key, 32, salt, SHA256, context=HKDF_INFO)

    # Step 6: Generate RSA key pair
    rsa_key = RSA.generate(RSA_KEY_SIZE)
    public_key = rsa_key.publickey().export_key()
    private_key = rsa_key.export_key()

    # Step 7-8: Encrypt the symmetric key and private RSA key
    symmetric_key = get_random_bytes(CHA_CHA20_KEY_SIZE)
    encrypted_symmetric_key = encrypt_data(stretched_master_key, symmetric_key)
    encrypted_private_key = encrypt_data(symmetric_key, private_key)

    # Step 9: Prepare data to send to server
    user_data = {
        'username': username,
        'master_password_hash': base64.urlsafe_b64encode(master_password_hash).decode(),
        'encrypted_symmetric_key': encrypted_symmetric_key,
        'public_key': base64.urlsafe_b64encode(public_key).decode(),
        'encrypted_private_key': encrypted_private_key
    }

    response = requests.post('http://localhost:5000/register', json=user_data)

    return response


def login(username, master_password):
    global client_index
    # Derive the master key using the hashed username as the salt
    salt = hash_username(username)
    master_key = argon2_hash(master_password, salt).encode('utf-8')[-16:]

    # Prepare the master key for encryption by ensuring it's the right size
    master_password_hash = argon2_hash(master_password, master_key).encode('utf-8')[-16:]

    stretched_master_key = HKDF(master_key, 32, salt, SHA256, context=HKDF_INFO)

    # Send the hashed username and master key to the server for authentication
    login_data = {
        'username': username,
        'master_password_hash': base64.urlsafe_b64encode(master_password_hash).decode()
    }

    # Make a request to the server's login endpoint
    response = requests.post('http://localhost:5000/login', json=login_data)

    if response.status_code == 200:
        # If login is successful, decrypt the received keys
        keys = response.json()
        encrypted_symmetric_key = base64.urlsafe_b64decode(keys['encrypted_symmetric_key'])
        encrypted_private_key = base64.urlsafe_b64decode(keys['encrypted_private_key'])

        IV, tag, ciphertext = extract_chacha_cipher_infos(encrypted_symmetric_key)
        # Use the master key to decrypt the symmetric key
        cipher = ChaCha20_Poly1305.new(key=stretched_master_key, nonce=IV)

        symmetric_key = cipher.decrypt_and_verify(ciphertext, tag)

        IV, tag, ciphertext = extract_chacha_cipher_infos(encrypted_private_key)
        # Use the symmetric key to decrypt the private key
        cipher = ChaCha20_Poly1305.new(key=symmetric_key, nonce=IV)
        private_key = cipher.decrypt_and_verify(ciphertext, tag)

        client_index.symmetric_key = symmetric_key
        client_index.private_key = private_key

        print("Login successful. Symmetric and private keys retrieved.")
        return response
    else:
        print("Login failed:", response.json().get('error', 'Unknown error'))
        return response


def change_password(username, old_master_password, new_master_password):
    # To change the password, the user must first log in with the old password
    # If login is successful, proceed to update the user's credentials with the new password
    login_response, symmetric_key, private_key = login(username, old_master_password)
    if login_response.status_code == 200:
        salt = hash_username(username)
        new_master_key = argon2_hash(new_master_password, salt).encode('utf-8')[-16:]

        # Prepare the master key for encryption by ensuring it's the right size
        new_master_password_hash = argon2_hash(new_master_password, new_master_key).encode('utf-8')[-16:]
        # TODO UPDATE ALL NEW KEYS IN DB
        update_data = {
            'username': username,
            'new_master_password_hash': base64.urlsafe_b64encode(new_master_password_hash).decode()
        }

        return requests.post('http://localhost:5000/change_password', json=update_data)
    else:
        return login_response


def create_folder(folder_name):
    encrypted_folder_name = encrypt_data(client_index.symmetric_key, folder_name.encode())
    client_index.add_folder(folder_name, encrypted_folder_name)
    print(client_index.index)
    new_folder = {
        'encrypted_folder_name': encrypted_folder_name,
    }
    # Send encrypted folder name and folder_info_json to the server
    return requests.post('http://localhost:5000/create_folder', json=new_folder)


def list_directories():
    response = requests.post('http://localhost:5000/list_directories')
    if response.status_code == 200:
        directories = response.json()
        print("\nDirectories and files in your vault:")
        print_tree(directories, client_index.symmetric_key)
    else:
        print("Failed to retrieve directories")


def print_tree(structure, symmetric_key, indent=0):
    for name, sub_structure in structure.items():
        IV, tag, ciphertext = extract_chacha_cipher_infos(base64.urlsafe_b64decode(name))
        cipher = ChaCha20_Poly1305.new(key=symmetric_key, nonce=IV)

        decrypted_name = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        print(' ' * indent + decrypted_name)
        if isinstance(sub_structure, dict):  # It's a directory
            print_tree(sub_structure, symmetric_key, indent + 4)


def change_current_directory(new_curr_directory):
    encrypted_folder_name = encrypt_data(client_index.symmetric_key, new_curr_directory.encode())

    encrypted_new_curr_directory = {
        'encrypted_new_curr_directory': encrypted_folder_name,
    }
    response = requests.post('http://localhost:5000/change_directory', json=encrypted_new_curr_directory)

    if response.status_code == 200:
        directories = response.json()
        print("\nDirectories and files in your vault:")
        print_tree(directories, client_index.symmetric_key)
    else:
        print("Failed to retrieve directories")