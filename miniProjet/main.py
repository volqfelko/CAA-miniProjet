from client.client import *


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
                print("\n" + "*" * 30 + "\nLogin successful.\n" + "*" * 30)
                while True:
                    print("\nWelcome " + str(username) + "\n")
                    print("1. Upload File")
                    print("2. Create folder")
                    print("3. List directories")
                    print("4. Change directory")
                    print("5. Change Password")
                    print("6. Exit")
                    choice = input("Choose an option: ")

                    if choice == '2':
                        folder_name = input("Enter folder name to create: ")
                        create_folder(folder_name)
                        if response.status_code == 200:
                            print("\n" + "*" * 30 + "\nFolder " + str(folder_name) + " created.\n" + "*" * 30)
                        else:
                            print("Folder creation failed: " + response.json().get('error', 'Unknown error'))

                    elif choice == '3':
                        if response.status_code == 200:
                            list_directories()
                        else:
                            print("File listing failed: " + response.json().get('error', 'Unknown error'))

                    elif choice == '4':
                        if response.status_code == 200:
                            choice = input("wich directory do you want to move to ? ")
                            change_current_directory(choice)
                        else:
                            print("Directory moving failed: " + response.json().get('error', 'Unknown error'))

                    elif choice == '5':
                        username = input("Enter your username: ")
                        old_password = input("Enter your old master password: ")
                        new_password = input("Enter your new master password: ")
                        response = change_password(username, old_password, new_password)
                        if response.status_code == 200:
                            print("\n" + "*" * 30 + "\nPassword changed successfully.\n" + "*" * 30)
                        else:
                            print("Password change failed: " + response.json().get('error', 'Unknown error'))

                    elif choice == '5':
                        print("Exiting the application.")
                        return
            else:
                print("Login failed: " + response.json().get('error', 'Unknown error'))

        elif choice == '3':
            print("Exiting the application.")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
