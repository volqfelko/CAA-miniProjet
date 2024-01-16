# Class to handle client-side indexing
class ClientIndex:
    def __init__(self, symmetric_key, symmetric_key_encrypted, private_key, private_key_encrypted):
        self.symmetric_key = symmetric_key
        self.symmetric_key_encrypted = symmetric_key_encrypted
        self.private_key = private_key
        self.private_key_encrypted = private_key_encrypted
        self.index = []  # This will store the mapping of plaintext names to encrypted names

    # Function to add a folder to the index
    def add_folder(self, plain_folder_name, encrypted_folder_name):
        self.index[plain_folder_name] = encrypted_folder_name


# Function to retrieve an encrypted folder name
def find_encrypted_directory_name(directory_structure, encrypted_name, file_type):
    for entry in directory_structure:
        entry_name = entry[1]
        if entry_name == encrypted_name and entry[0] == file_type:
            return entry[2]  # Return the associated decrypted name

        # If there are subfolders, recursively search them
        if len(entry) == 4:  # Check if there is a subfolder list in the entry
            found = find_encrypted_directory_name(entry[3], encrypted_name, file_type)
            if found is not None:
                return found

    return None  # Return None if the directory is not found


def find_decrypted_directory_name(directory_structure, decrypted_name, file_type):
    for entry in directory_structure:
        entry_name = entry[2]
        if entry_name == decrypted_name and entry[0] == file_type:
            return entry[1]  # Return the associated decrypted name

        # If there are subfolders, recursively search them
        if len(entry) == 4:  # Check if there is a subfolder list in the entry
            found = find_decrypted_directory_name(entry[3], decrypted_name, file_type)
            if found is not None:
                return found

    return None  # Return None if the directory is not found
