import requests

from client.client import *


def main():
    while True:
        print("\nWelcome to the Encrypted File System")
        print("1. Register")
        print("2. Login")
        print("3. Change Password")
        print("4. Exit")
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
            else:
                print("Login failed: " + response.json().get('error', 'Unknown error'))

        elif choice == '3':
            username = input("Enter your username: ")
            old_password = input("Enter your old master password: ")
            new_password = input("Enter your new master password: ")
            response = change_password(username, old_password, new_password)
            if response.status_code == 200:
                print("\n" + "*" * 30 + "\nPassword changed successfully.\n" + "*" * 30)
            else:
                print("Password change failed: " + response.json().get('error', 'Unknown error'))

        elif choice == '4':
            print("Exiting the application.")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
