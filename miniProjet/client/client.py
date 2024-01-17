import json
import os
import secrets
import requests

from Crypto.Protocol.KDF import HKDF
from client.crypto import *
from client.index import ClientIndex, find_encrypted_directory_name, find_decrypted_directory_name

client_index = ClientIndex(None, None, None, None)


def create_account(username, master_password):
    # Step 1-4: Generate master key with username as salt
    salt = hash_username(username)
    master_key = argon2_hash(master_password, salt).encode('utf-8')[-16:]

    # Step 5: Generate master password hash
    master_password_hash = argon2_hash(master_password, master_key).encode('utf-8')[-16:]

    #TODO salt HKDF ????
    stretched_master_key = HKDF(master_key, 32, salt, SHA256, context=HKDF_INFO)

    # Step 6: Generate RSA key pair
    public_key, private_key = generate_rsa_key_pair()

    # Step 7-8: Encrypt the symmetric key and private RSA key
    symmetric_key = secrets.randbits(CHA_CHA20_KEY_SIZE_BITS).to_bytes(CHA_CHA20_KEY_SIZE, byteorder='big')
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
        client_index.symmetric_key_encrypted = encrypted_symmetric_key
        client_index.private_key = private_key
        client_index.private_key_encrypted = encrypted_private_key

        #Decrypt everything in vault first login and populate client_index
        get_files_list()
        return response
    else:
        return response


def change_password(username, new_master_password):
    salt = hash_username(username)
    new_master_key = argon2_hash(new_master_password, salt).encode('utf-8')[-16:]

    # Prepare the master key for encryption by ensuring it's the right size
    new_master_password_hash = argon2_hash(new_master_password, new_master_key).encode('utf-8')[-16:]

    new_stretched_master_key = HKDF(new_master_key, 32, salt, SHA256, context=HKDF_INFO)

    # Encrypt symmetric and private keys with new stretched master key
    new_protected_symmetric_key = encrypt_data(new_stretched_master_key, client_index.symmetric_key)
    new_protected_private_key = encrypt_data(client_index.symmetric_key, client_index.private_key)

    update_data = {
        'username': username,
        'new_master_password_hash': base64.urlsafe_b64encode(new_master_password_hash).decode(),
        'new_protected_symmetric_key': new_protected_symmetric_key,
        'new_protected_private_key': new_protected_private_key
    }

    return requests.post('http://localhost:5000/change_password', json=update_data)


def upload_file(file_path):
    full_curr_path = get_full_curr_dir()
    exists, parent = find_parent_structure(client_index.index, full_curr_path)
    if exists:
        parent_symmetric_key = parent[3]
    else:
        parent_symmetric_key = client_index.symmetric_key

    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted_file = encrypt_data(parent_symmetric_key, original)

    file_name = file_path.split('\\')[-1]
    encrypted_file_name = encrypt_data(parent_symmetric_key, file_name.encode())

    datas = {
        'file_type': 'file',
        'encrypted_file_name': encrypted_file_name,
        'parent_symmetric_key': base64.urlsafe_b64encode(parent_symmetric_key).decode()
    }

    files = {'file': (encrypted_file_name, encrypted_file)}

    # Send the encrypted file to the server
    response = requests.post('http://localhost:5000/file_upload', files=files, params=datas)

    entry = ['file', file_name, encrypted_file_name]
    result = insert_entry_in_structure(client_index.index, full_curr_path, entry)

    if result is False:
        print("Failed to create folder at right index")
        return

    return response


def get_full_curr_dir():
    response = requests.get('http://localhost:5000/get_full_curr_dir')
    if response.status_code == 200:
        data = response.json()
        return data['full_cur_path']
    else:
        return response


def get_curr_dir():
    response = requests.get('http://localhost:5000/get_curr_dir')
    if response.status_code == 200:
        data = response.json()
        return data['curr_dir']
    else:
        return response


def download_file(file_name):
    destination_path = os.getcwd() + "/client/downloads/"
    try:
        encrypted_file_name = find_encrypted_directory_name(client_index.index, file_name, 'file')

        if encrypted_file_name is None:
            return "file not found"

        response = requests.get('http://localhost:5000/download_file', params={'encrypted_file_name': encrypted_file_name}, stream=True)
        response.raise_for_status()

        encrypted_content = b''
        for chunk in response.iter_content(chunk_size=8192):
            encrypted_content += chunk

        encrypted_content_b64 = encrypted_content.decode('utf-8')
        padded_encrypted_content = pad_base64(encrypted_content_b64)

        full_curr_path = get_full_curr_dir()
        exists, parent = find_parent_structure(client_index.index, full_curr_path)
        if exists:
            parent_symmetric_key = parent[3]
        else:
            parent_symmetric_key = client_index.symmetric_key

        IV, tag, ciphertext = extract_chacha_cipher_infos(base64.urlsafe_b64decode(padded_encrypted_content))
        # Use the symmetric key to decrypt the private key
        cipher = ChaCha20_Poly1305.new(key=parent_symmetric_key, nonce=IV)
        decrypted_content = cipher.decrypt_and_verify(ciphertext, tag)

        # Write the decrypted content to a file
        full_path = os.path.join(destination_path, file_name)
        with open(full_path, 'wb') as f:
            f.write(decrypted_content)

        return "File downloaded successfully."
    except requests.exceptions.HTTPError as errh:
        return f"HTTP Error: {errh}"
    except requests.exceptions.ConnectionError as errc:
        return f"Error Connecting: {errc}"
    except requests.exceptions.Timeout as errt:
        return f"Timeout Error: {errt}"
    except requests.exceptions.RequestException as err:
        return f"Error: {err}"


def create_folder(plain_folder_name):
    full_curr_path = get_full_curr_dir()

    if full_curr_path == "":
        encrypted_folder_name = encrypt_data(client_index.symmetric_key, plain_folder_name.encode())
        symmetric_key_encrypted = client_index.symmetric_key_encrypted
        client_entry = ['directory', plain_folder_name, encrypted_folder_name, client_index.symmetric_key, symmetric_key_encrypted]
        server_entry = ['directory', '', encrypted_folder_name, '',
                        base64.urlsafe_b64encode(symmetric_key_encrypted).decode()]
    else:
        new_plain_symmetric_key = secrets.randbits(CHA_CHA20_KEY_SIZE_BITS).to_bytes(CHA_CHA20_KEY_SIZE, byteorder='big')
        encrypted_folder_name = encrypt_data(new_plain_symmetric_key, plain_folder_name.encode())
        exists, parent_directory = find_parent_structure(client_index.index, full_curr_path)
        parent_directory_symmetric_key = parent_directory[3]
        symmetric_key_encrypted = encrypt_data(parent_directory_symmetric_key, new_plain_symmetric_key)
        client_entry = ['directory', plain_folder_name, encrypted_folder_name, new_plain_symmetric_key, symmetric_key_encrypted]
        server_entry = ['directory', '', encrypted_folder_name, '', symmetric_key_encrypted]

    result = insert_entry_in_structure(client_index.index, full_curr_path, client_entry)
    if result is False:
        print("Failed to create folder at right index")
        return


    new_folder = {
        'encrypted_folder_name': encrypted_folder_name,
        'server_entry': server_entry
    }

    # Send encrypted folder name and folder_info_json to the server
    return requests.post('http://localhost:5000/create_folder', json=new_folder)


def insert_entry_in_structure(directory_structure, path, new_entry):
    def recurse_and_insert(structure, path_components):
        current_component = path_components[0]
        for entry in structure:
            if entry[0] in ['directory', 'file'] and entry[2] == current_component:
                if entry[0] == 'directory':
                    if len(entry) <= 5:
                        entry.append([])  # Ensure there's a list to append to if it doesn't exist
                    if len(path_components) == 1:
                        # Insert the new entry in the current directory
                        entry[5].append(new_entry)
                        return True
                    # Recurse into the directory
                    return recurse_and_insert(entry[5], path_components[1:])
        return False

    # Check if path is empty and insert new_entry at the next index
    path_components = path.split('\\')
    if not path_components or path_components == ['']:
        directory_structure.append(new_entry)
        return True

    return recurse_and_insert(directory_structure, path_components)


def find_parent_structure(directory_structure, path):
    path_components = path.split('\\')

    def traverse(structure, index=0):
        for entry in structure:
            if index >= len(path_components):
                # Return the parent structure for the last path component
                return True, entry
            elif entry[0] == 'directory' and entry[2] == path_components[index]:
                # If it's a directory and the name matches, go deeper
                if len(entry) > 5 and isinstance(entry[5], list):
                    return traverse(entry[5], index + 1)
                elif index == len(path_components) - 1:
                    return True, entry
            elif entry[0] == 'file' and entry[2] == path_components[index]:
                # If it's a file and it's the last component in the path
                if index == len(path_components) - 1:
                    return True, entry

        return False, None

    # Handle the case where the path is only one component
    if len(path_components) == 1:
        for entry in directory_structure:
            if entry[0] in ['directory', 'file'] and entry[2] == path_components[0]:
                return True, entry

    return traverse(directory_structure)


def get_files_list():
    response = requests.post('http://localhost:5000/get_personal_file_struct')
    if response.status_code == 200:
        directories = response.json()
        decrypt_all_files_and_complete_list(directories, client_index.symmetric_key)
    else:
        print("Failed to retrieve directories")


def change_current_directory(new_curr_directory):
    # TODO GO BACKWARDS, FOR NOW IT ONLY GOES FORWARD
    encrypted_folder_name = find_encrypted_directory_name(client_index.index, new_curr_directory, 'directory')
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


def pad_base64(b64string):
    """ Pad the base64 string to the correct length with '=' characters. """
    padding = 4 - (len(b64string) % 4)
    return b64string + ("=" * padding)


def decrypt_all_files_and_complete_list(directory_structure, symmetric_key, depth=0, parent_symmetric_key=None):
    for entry in directory_structure:
        current_symmetric_key = symmetric_key if depth == 0 else parent_symmetric_key

        if entry[0] == 'directory':
            # Decrypt the nested directory's symmetric key if depth > 0
            nested_symmetric_key = decrypt_data2(current_symmetric_key, base64.urlsafe_b64decode(entry[4])) if depth > 0 else symmetric_key

            # Decrypt the folder name
            padded_folder_name = pad_base64(entry[2])
            decrypted_folder_name = decrypt_data2(nested_symmetric_key, base64.urlsafe_b64decode(padded_folder_name))
            entry[1] = decrypted_folder_name.decode()

            entry[3] = nested_symmetric_key
            # Recursively process subdirectories
            if len(entry) > 5:
                decrypt_all_files_and_complete_list(entry[5], symmetric_key, depth + 1, nested_symmetric_key)

        elif entry[0] == 'file':
            # Decrypt file name with the parent directory's symmetric key
            entry[3] = current_symmetric_key
            padded_file_name = pad_base64(entry[2])
            decrypted_file_name = decrypt_data2(current_symmetric_key, base64.urlsafe_b64decode(padded_file_name)).decode()
            entry[1] = decrypted_file_name

    client_index.index = directory_structure


def decrypt_data2(key, data):
    IV, tag, ciphertext = extract_chacha_cipher_infos(data)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=IV)
    return cipher.decrypt_and_verify(ciphertext, tag)


def print_tree_structure(directory_structure, indent_level=0):
    indent = '    ' * indent_level  # 4 spaces per indentation level
    for entry in directory_structure:
        # Print the folder name
        folder_name = entry[1]
        print(f"{indent}{folder_name}")

        # If there are subfolders, recursively print them with increased indentation
        if len(entry) > 5:  # Check if there is a suvbfolder list in the entry
            print_tree_structure(entry[5], indent_level + 1)