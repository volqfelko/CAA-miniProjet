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

        #Decrypt everything in vault first login and populate client_index
        get_files_list()
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


def upload_file(file_path):
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted_file = encrypt_data(client_index.symmetric_key, original)

    file_name = file_path.split('\\')[-1]
    encrypted_file_name = encrypt_data(client_index.symmetric_key, file_name.encode())
    files = {'file': (encrypted_file_name, encrypted_file)}

    # Send the encrypted file to the server
    response = requests.post('http://localhost:5000/file_upload', files=files)

    return response


def create_folder(folder_name):
    response = requests.get('http://localhost:5000/get_curr_dir')
    encrypted_folder_name = encrypt_data(client_index.symmetric_key, folder_name.encode())
    # TODO UPDATE CLIENT INDEX AT EACH FOLDER CREATION
    #client_index.add_folder(folder_name, encrypted_folder_name)
    new_folder = {
        'encrypted_folder_name': encrypted_folder_name,
    }
    # Send encrypted folder name and folder_info_json to the server
    return requests.post('http://localhost:5000/create_folder', json=new_folder)


def get_files_list():
    response = requests.post('http://localhost:5000/list_directories')
    if response.status_code == 200:
        directories = response.json()
        decrypt_all_files_and_complete_list(directories)
    else:
        print("Failed to retrieve directories")


def decrypt_all_files_and_complete_list(structure):
    for entry in structure:
        folder_name = entry[2]
        IV, tag, ciphertext = extract_chacha_cipher_infos(base64.urlsafe_b64decode(folder_name))
        cipher = ChaCha20_Poly1305.new(key=client_index.symmetric_key, nonce=IV)

        decrypted_name = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        entry[1] = decrypted_name
        if entry[0] == 'directory' and len(entry) > 3:  # It's a directory
            decrypt_all_files_and_complete_list(entry[3])

    client_index.index = structure


def print_tree_structure(directory_structure, indent_level=0):
    indent = '    ' * indent_level  # 4 spaces per indentation level
    for entry in directory_structure:
        # Print the folder name
        folder_name = entry[1]
        print(f"{indent}{folder_name}")

        # If there are subfolders, recursively print them with increased indentation
        if len(entry) > 3:  # Check if there is a suvbfolder list in the entry
            print_tree_structure(entry[3], indent_level + 1)


def change_current_directory(new_curr_directory):
    encrypted_folder_name = find_directory_name(client_index.index, new_curr_directory)
    if encrypted_folder_name is None:
        print("Directory not found")
        return

    encrypted_new_curr_directory = {
        'encrypted_new_curr_directory': encrypted_folder_name,
    }
    response = requests.post('http://localhost:5000/change_directory', json=encrypted_new_curr_directory)

    if response.status_code == 200:
        print("Changed directory successfully")
    else:
        print("Failed to change directory")


def find_directory_name(directory_structure, directory_name):
    for entry in directory_structure:
        folder_name = entry[1]
        if folder_name == directory_name and entry[0] == 'directory':
            return entry[2]  # Return the associated decrypted name

        # If there are subfolders, recursively search them
        if len(entry) == 4:  # Check if there is a subfolder list in the entry
            found = find_directory_name(entry[3], directory_name)
            if found is not None:
                return found

    return None  # Return None if the directory is not found


def get_curr_dir():
    response = requests.get('http://localhost:5000/get_curr_dir')
    datas = response.json()
    #TODO PRINT DECRYPTED CURRENT DIRECTORY TO RETRIEVE IN LIST INDEX
    if response.status_code == 200:
        print("Current directory: " + str(datas['curr_dir'] + "\n"))
    else:
        return None