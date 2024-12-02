import os
import json

## ======================================================================
## This script adds default aliases to all libraries that need them.
##
## That is, if a function had a default name like FUNCTION_0003 but was 
## at some point given a real name like SEL, that default name will be 
## added as an alias. 
##
## This allows flowscript files that were decompiled prior to the name
## being updated to still work.
##
## Note that some of the games had their function names included in the
## executable so they never had these unknown names. These are excluded
## from this script. Seee the ignoredFolders variable below.
## ======================================================================

# Path to the libraries
folder_path = 'Source/AtlusScriptLibrary/Libraries'
    
# Folders to ignore since the game's contained the real function names
ignoredFolders = [
    "SMT3",
    "Persona5",
    "Persona5Royal",
    "Persona3Reload",
    "Catherine",
    "CatherineFullBody"
]

def is_ignored_folder(folder: str) -> bool:
    for ignored in ignoredFolders:
        if ignored in folder:
            return True
    return False

def get_folder_prefix(folder_name):
    # Define folder-specific prefixes
    folder_prefixes = {
        'AI': 'AI_',
        'Battle': 'BTL_',
        'Common': '',
        'Camp': 'CAMP_',
        'Dungeon': 'DNG_',
        'Event': 'EVT_',
        'Facility': 'FCL_',
        'Field': 'FLD_',
        "Map": 'MAP_',
        'Net': 'NET_',
        'Script': 'SCR_',
        'Shared': 'SHD_',
        'Window': 'WND_',
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
    with open(file_path, 'r', encoding='utf-8-sig') as file:
        data = json.load(file)

    # Iterate through each function in the array and add the alias
    for function in data:
        add_alias_to_function(function, folder_prefix)

    # Write the modified JSON back to the file
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=2)

def process_folder(folder_path):
    for root, dirs, files in os.walk(folder_path):
        if not is_ignored_folder(root):
            for file in files:
                if file.endswith('Functions.json'):
                    file_path = os.path.join(root, file)
                    process_json_file(file_path)

if __name__ == "__main__":
    process_folder(folder_path)