from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import os
import json

app = Flask(__name__)
users_file = 'users.json'
UPLOAD_FOLDER = 'uploads'


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

    # Save new user data
    users[username] = user_data
    with open(users_file, 'w') as file:
        json.dump(users, file, indent=2)

    return jsonify({"success": True}), 200


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


@app.route('/upload_file', methods=['POST'])
def upload_file():
    # Check if the user is authenticated
    # ...

    file = request.files['file']
    filename = secure_filename(file.filename)
    user_folder = os.path.join(UPLOAD_FOLDER, username)

    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    file_path = os.path.join(user_folder, filename)
    file.save(file_path)

    # Encrypt the file after saving
    # ...

    return jsonify({'success': 'File uploaded and encrypted successfully.'}), 200


@app.route('/download_file/<filename>', methods=['GET'])
def download_file(filename):
    # Check if the user is authenticated
    # ...

    user_folder = os.path.join(UPLOAD_FOLDER, username)
    file_path = os.path.join(user_folder, filename)

    # Decrypt the file before sending
    # ...

    return send_from_directory(user_folder, filename, as_attachment=True)


app.run(debug=True, port=5000)