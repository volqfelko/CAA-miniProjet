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
        if len(entry) == 6:  # Check if there is a subfolder list in the entry
            found = find_encrypted_directory_name(entry[5], encrypted_name, file_type)
            if found is not None:
                return found

    return None  # Return None if the directory is not found


def find_file_in_structure(structure, path_str, plain_name):
    def find_subfolder(folder, subfolder_name):
        for item in folder:
            if item[0] == 'directory' and item[2] == subfolder_name:
                return item[5]  # The subfolder list
        return None

    # Check if the path string is empty and set the current structure accordingly
    if path_str == "":
        current_structure = structure
    else:
        # Split the path string into a list of folder names
        path = path_str.split('\\')

        # Navigate to the given path
        current_structure = structure
        for folder_name in path:
            current_structure = find_subfolder(current_structure, folder_name)
            if current_structure is None:
                return f"Path '{path_str}' does not exist."

    # Search for the file in the final directory
    for item in current_structure:
        if item[0] != 'directory' and item[1] == plain_name:
            return item

    return f"File '{plain_name}' not found in '{path_str}'."


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


def find_directory_by_encrypted_name(structure, encrypted_dir_name):
    def find_directory(folder, encrypted_name):
        for item in folder:
            # Check if the item is a directory and matches the encrypted name
            if item[0] == 'directory' and item[2] == encrypted_name:
                return item[1]  # Return the decrypted (plain) name of the directory
        return None

    # Recursively search in the structure
    def search_recursive(folder):
        result = find_directory(folder, encrypted_dir_name)
        if result:
            return result
        for item in folder:
            if item[0] == 'directory' and len(item) > 5:
                # Search in subdirectories
                sub_result = search_recursive(item[5])
                if sub_result:
                    return sub_result
        return None

    # Start the recursive search from the root structure
    return search_recursive(structure)