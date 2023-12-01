import os
import json

def get_folder_prefix(folder_name):
    # Define folder-specific prefixes
    folder_prefixes = {
        'AI': 'AI_',
        'Common': '',
        'Event': 'EVT_',
        'Facility': 'FCL_',
        'Field': 'FLD_',
        'Shared': 'SHD_',
        'Net': 'NET_',
        # Add more folder names and prefixes as needed
    }
    
    # Return the prefix or an empty string if the folder is not in the dictionary
    return folder_prefixes.get(folder_name, '')

def add_alias_to_function(function, folder_prefix):
    # Check if "Aliases" key already exists
    if 'Aliases' not in function:
        # Add "Aliases" key with the new alias
        function_id = function.get('Index', '')
        alias = folder_prefix + 'FUNCTION_' + function_id[3:].zfill(4).upper()
        if function.get('Name', '') != alias:
            function['Aliases'] = [alias]

def process_json_file(file_path):
    # Extract the folder name from the file path
    folder_name = os.path.basename(os.path.dirname(file_path))
    
    # Get the folder-specific prefix
    folder_prefix = get_folder_prefix(folder_name)

    print(f"Parsing {file_path}")
    with open(file_path, 'r') as file:
        data = json.load(file)

    # Iterate through each function in the array and add the alias
    for function in data:
        add_alias_to_function(function, folder_prefix)

    # Write the modified JSON back to the file
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=2)

def process_folder(folder_path):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('Functions.json'):
                file_path = os.path.join(root, file)
                process_json_file(file_path)

# Path to the libraries
folder_path = '../Source/AtlusScriptLibrary/Libraries'
process_folder(folder_path)
