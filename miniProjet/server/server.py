import base64

from flask import Flask, request, jsonify
import os
import json

app = Flask(__name__)

users_file = 'users.json'
FILESYSTEM = 'filesystem'


def update_curr_dir(new_dir):
    global FILESYSTEM
    FILESYSTEM = os.path.join(FILESYSTEM, new_dir)


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


@app.route('/create_folder', methods=['POST'])
def handle_create_folder():
    # Extract user's personal folder path
    new_folder = request.json
    encrypted_folder_name = new_folder['encrypted_folder_name']
    app.logger.warning(base64.urlsafe_b64decode(encrypted_folder_name))
    # Create new folder with encrypted name
    new_folder_path = os.path.join(FILESYSTEM, encrypted_folder_name)
    app.logger.warning(new_folder_path)
    os.makedirs(new_folder_path, exist_ok=True)


@app.route('/list_directories', methods=['POST'])
def list_user_directories():
    # Recursive function to get directory structure
    def get_directory_structure(path):
        structure = {}
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if os.path.isdir(item_path):
                structure[item] = get_directory_structure(item_path)
            else:
                structure[item] = None  # or some file information
        return structure

    directory_structure = get_directory_structure(FILESYSTEM)
    return jsonify(directory_structure), 200


@app.route('/change_directory', methods=['POST'])
def change_current_directory():
    request_data = request.json
    new_curr_directory = request_data['encrypted_new_curr_directory']

    # Check if the new directory exists
    if not os.path.exists(new_curr_directory):
        return jsonify({"error": "Directory does not exist"}), 404

    try:
        # Change the current working directory
        update_curr_dir(new_curr_directory)
        return jsonify({"success": True, "current_directory": new_curr_directory}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


app.run(debug=True, port=5000)

