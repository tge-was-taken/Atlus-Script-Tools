import json
import glob

# This scripts syncs FlowScript function names from SMT3 (HD) to other PS2 SMT games.
# These games share a lot of functions, so even though some will be incorrect, most will be correct.
# This takes function index & parameter count into account, so the library is guaranteed to function correctly regardless.

def load_json(file_path):
    """Load JSON data from a file."""
    with open(file_path, 'r', encoding='utf-8-sig') as f:
        return json.load(f)

def save_json(file_path, data):
    """Save JSON data to a file."""
    with open(file_path, 'w', encoding='utf-8-sig') as f:
        json.dump(data, f, indent=4)

def compare_and_update_jsons(base_file, other_files):
    """
    Compare the base JSON file with other JSON files and update the other
    file where Index and Parameters count match.
    """
    # Load the base JSON file
    base_data = load_json(base_file)
    
    for file in other_files:
        if file == base_file:
            continue
        
        other_data = load_json(file)
        
        for base_item in base_data:
            for other_item in other_data:
                if (other_item['Name'].startswith('FUNCTION_') and
                    other_item['Description'] != 'Null pointer' and
                    base_item['Description'] != 'Null pointer' and
                    base_item['Index'] == other_item['Index'] and 
                    len(base_item['Parameters']) == len(other_item['Parameters'])):
                    # Overwrite attributes
                    other_item.update({
                        "ReturnType": base_item["ReturnType"],
                        "Name": base_item["Name"],
                        "Description": base_item["Description"] + ' (Copied from SMT3. May be incorrect.)',
                        "Parameters": base_item["Parameters"],
                        "FullName": base_item["FullName"]
                    })

        save_json(file, other_data)

# Example usage
if __name__ == "__main__":
    # Base JSON file to be updated
    base_file = "Source/AtlusScriptLibrary/Libraries/SMT3/Modules/Common/Functions.json"
    
    json_files = [
        "Source/AtlusScriptLibrary/Libraries/DigitalDevilSaga/Modules/Common/Functions.json",
        "Source/AtlusScriptLibrary/Libraries/DigitalDevilSaga2/Modules/Common/Functions.json",
        "Source/AtlusScriptLibrary/Libraries/Raidou/Modules/Common/Functions.json",
        "Source/AtlusScriptLibrary/Libraries/Raidou2/Modules/Common/Functions.json",
    ]
    
    # Compare and update the base file
    compare_and_update_jsons(base_file, json_files)
