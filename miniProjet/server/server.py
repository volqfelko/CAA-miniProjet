from flask import Flask, request, jsonify
import os
import json

from werkzeug.utils import secure_filename

app = Flask(__name__)

users_file = 'users.json'
FILESYSTEM = 'filesystem'


def update_curr_dir(new_dir):
    global FILESYSTEM
    FILESYSTEM = os.path.join(FILESYSTEM, new_dir)


@app.route('/get_curr_dir', methods=['GET'])
def get_curr_dir():
    truncated_path = FILESYSTEM.split('\\')[-1]
    return jsonify({"curr_dir": truncated_path}), 200


@app.route('/register', methods=['POST'])
def register():
    user_data = request.json
    username = user_data['username']

    # Initialize users dictionary
    users = {}

    # Check if the file exists and is not empty
    if os.path.exists(users_file) and os.path.getsize(users_file) > 0:
        try:
            with open(users_file, 'r') as file:
                users = json.load(file)
        except json.JSONDecodeError:
            return jsonify({"error": "Error reading users file"}), 500

    if username in users:
        return jsonify({"error": "User already exists"}), 409

    # Create a folder for the user
    user_folder_path = os.path.join(FILESYSTEM, username)
    if not os.path.exists(user_folder_path):
        os.makedirs(user_folder_path)

    # Save new user data
    users[username] = user_data
    with open(users_file, 'w') as file:
        json.dump(users, file, indent=2)

    return jsonify({'success': 'User registered and personnal vault created'}), 200


@app.route('/login', methods=['POST'])
def login():
    login_data = request.json
    username = login_data['username']
    master_password_hash = login_data['master_password_hash']

    # Check user credentials
    if os.path.exists(users_file):
        with open(users_file, 'r') as file:
            users = json.load(file)
            if username in users and users[username]['master_password_hash'] == master_password_hash:
                encrypted_symmetric_key = users[username]['encrypted_symmetric_key']
                encrypted_private_key = users[username]['encrypted_private_key']

                encrypted_keys = {
                    'encrypted_symmetric_key': encrypted_symmetric_key,
                    'encrypted_private_key': encrypted_private_key
                }
                update_curr_dir(username)
                return jsonify(encrypted_keys), 200

            else:
                return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({"error": "User not found"}), 404


@app.route('/change_password', methods=['POST'])
def change_password():
    update_data = request.json
    username = update_data['username']
    new_master_password_hash = update_data['new_master_password_hash']

    # Update user's password
    if os.path.exists(users_file):
        with open(users_file, 'r+') as file:
            users = json.load(file)
            if username in users:
                users[username]['master_password_hash'] = new_master_password_hash
                file.seek(0)
                file.write(json.dumps(users))
                file.truncate()
                return jsonify({"success": True}), 200
    return jsonify({"error": "User not found"}), 404


@app.route('/file_upload', methods=['POST'])
def file_upload():
    # Check if a file is part of the request
    if 'file' not in request.files:
        return "No file part in the request", 400

    file = request.files['file']

    # If the user does not select a file
    if file.filename == '':
        return "No file selected", 400

    # Save the file
    filename = secure_filename(file.filename)
    file.save(os.path.join(FILESYSTEM, filename))

    return "File uploaded successfully", 200


@app.route('/create_folder', methods=['POST'])
def handle_create_folder():
    # Extract user's personal folder path
    new_folder = request.json
    encrypted_folder_name = new_folder['encrypted_folder_name']
    # Create new folder with encrypted name
    new_folder_path = os.path.join(FILESYSTEM, encrypted_folder_name)
    app.logger.warning(new_folder_path)
    os.makedirs(new_folder_path, exist_ok=True)
    return jsonify({"success": True, "Created directory": new_folder_path}), 200


@app.route('/list_directories', methods=['POST'])
def list_user_directories():
    # Recursive function to get directory and file structure
    def get_directory_structure(path):
        structure = []
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if os.path.isdir(full_path):
                # Recursive call for subfolders
                subfolders = get_directory_structure(full_path)

                # 'Decrypted name' is a placeholder string "name"
                decrypted_name = ""

                # Add tuple with or without subfolders list based on its presence
                if subfolders:
                    structure.append(('directory', decrypted_name, item, subfolders))
                else:
                    structure.append(('directory', decrypted_name, item))
            else:
                # Handle files
                decrypted_name = ""  # Replace with actual decrypted name if necessary
                structure.append(('file', decrypted_name, item))

        return structure

    directory_structure = get_directory_structure(FILESYSTEM)
    return jsonify(directory_structure), 200


@app.route('/change_directory', methods=['POST'])
def change_current_directory():
    request_data = request.json
    encrypted_directory_name = request_data['encrypted_new_curr_directory']
    # Check if the new directory exists
    if not os.path.join(FILESYSTEM, encrypted_directory_name):
        return jsonify({"error": "Directory does not exist"}), 404

    try:
        # Change the current working directory
        update_curr_dir(encrypted_directory_name)
        return jsonify({"success": True, "current_directory": encrypted_directory_name}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


app.run(debug=True, port=5000)

