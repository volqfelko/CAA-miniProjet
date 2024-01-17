from client.client import (create_account, login, upload_file, download_file,
                           create_folder, change_password, print_tree_structure,
                           change_current_directory, client_index, get_curr_dir)


def main():
    while True:
        print("\nWelcome to the Encrypted File System")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            username = input("Enter a new username: ")
            master_password = input("Enter a new master password: ")
            response = create_account(username, master_password.encode('utf-8'))
            if response.status_code == 200:
                print("\n" + "*" * 30 + "\nAccount created successfully.\n" + "*" * 30)
            else:
                print("An error occurred: " + response.json().get('error', 'Unknown error'))

        elif choice == '2':
            username = input("Enter your username: ")
            master_password = input("Enter your master password: ")
            response = login(username, master_password.encode('utf-8'))
            if response.status_code == 200:
                print("\n" + "*" * 30 + "\nLogin successful !"
                                        "\nSymmetric and private keys retrieved."
                                        "\nVault Decrypted."
                                        "\n" + "*" * 30)
                print("\nWelcome " + str(username) + "\n")
                while True:
                    get_curr_dir()
                    print("1. Upload File")
                    print("2. Download File")
                    print("3. Create folder")
                    print("4. List directories")
                    print("5. Change directory")
                    print("6. Change Password")
                    print("7. Exit")
                    choice = input("\n" + "Choose an option: ")

                    if choice == '1':
                        file_path = input("Enter file path to upload: ")
                        response = upload_file(file_path)
                        if response.status_code == 200:
                            print("\n" + "*" * 30 + "\nFile " + str(file_path) + " uploaded.\n" + "*" * 30)
                        else:
                            print("\n" + "File upload failed: " + response.json().get('error', 'Unknown error'))

                    elif choice == '2':
                        file_name = input("Enter a file name to download: ")
                        print(download_file(file_name))

                    elif choice == '3':
                        folder_name = input("Enter folder name to create: ")
                        create_folder(folder_name)
                        if response.status_code == 200:
                            print("\n" + "*" * 30 + "\nFolder " + str(folder_name) + " created.\n" + "*" * 30)
                        else:
                            print("\n" + "Folder creation failed: " + response.json().get('error', 'Unknown error'))

                    elif choice == '4':
                        if response.status_code == 200:
                            print("\nDirectories and files in your vault:\n")
                            print_tree_structure(client_index.index)
                        else:
                            print("\n" + "File listing failed: " + response.json().get('error', 'Unknown error'))

                    elif choice == '5':
                        if response.status_code == 200:
                            choice = input("\n" + "wich directory do you want to move to ? ")
                            change_current_directory(choice)
                            change_current_directory(choice)
                        else:
                            print("\n" + "Directory moving failed: " + response.json().get('error', 'Unknown error'))

                    elif choice == '6':
                        new_password = input("Enter your new master password: ")
                        response = change_password(username, new_password)
                        if response.status_code == 200:
                            print("\n" + "*" * 30 + "\nPassword changed successfully.\n" + "*" * 30)
                        else:
                            print("\n" + "Password change failed: " + response.json().get('error', 'Unknown error'))

                    elif choice == '7':
                        print("\n" + "Exiting the application.")
                        return
            else:
                print("\n" + "Login failed: " + response.json().get('error', 'Unknown error'))

        elif choice == '3':
            print("\n" + "Exiting the application.")
            break

        else:
            print("\n" + "Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
