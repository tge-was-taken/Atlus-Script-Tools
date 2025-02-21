import json
import re
import shutil
import idaapi
import idautils
import idc
import ida_hexrays
import ida_funcs
#
# scrGetIntPara is at 0x020B4718
# scrSetIntReturnValue is at 0x020B480C

# Address of the scrCommandTableArray with 4 elements
COMMAND_TABLE_ARRAY_ADDR = 0x020C65EC
CATEGORY_NAMES = ["Common"]
ARRAY_COUNT = len(CATEGORY_NAMES)

# Output directory for JSON files
OUTPUT_DIR = "scrCommandTables/"

# Ensure the output directory exists
import os
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Regex patterns for parameter analysis and return type
INDEX_REGEX = re.compile(r'scrGet(Int|Float)Para\s*\(\s*(?:\(.*?\)\s*)?(\d+)\s*\)')
RESULT_REGEX = re.compile(r'scrSet(Int|Float)ReturnValue')

# Helper function to read a null-terminated string
def read_cstring(addr):
    result = ""
    while True:
        char = idc.get_wide_byte(addr)
        if char == 0:
            break
        result += chr(char)
        addr += 1
    return result

# Helper function to sanitize a command name for use in function names
def sanitize_name(name):
    # Replace spaces or invalid characters with underscores
    return "".join(c if c.isalnum() else "_" for c in name)

# Helper function to decompile a function
def try_decompile(func_addr):
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays decompiler is not available")
        return None
    try:
        func = idaapi.get_func(func_addr)
        if func:
            return ida_hexrays.decompile(func)
    except Exception as e:
        print(f"Error decompiling function at {hex(func_addr)}: {e}")
    return None

# Helper function to analyze a function and determine parameter types and return type
def analyze_function(func_addr):
    ida_funcs.add_func(func_addr)

    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays decompiler is not available")
        return {}, "void"
    
    try:
        # Decompile the function
        decompiled = try_decompile(func_addr)
        if not decompiled:
            print(f"Failed to decompile function at {hex(func_addr)}")
            return {}, "void"
        
        # Extract the decompiled pseudocode
        pseudocode = decompiled.get_pseudocode()
        parameter_map = {}
        return_type = "void"
        
        for line in pseudocode:
            text = ida_lines.tag_remove(line.line)
            
            # Use regex to find calls to scrGetIntPara or scrGetFloatPara
            param_matches = INDEX_REGEX.findall(text)
            for match in param_matches:
                param_type, index_value = match
                index = int(index_value)
                parameter_map[index] = "int" if param_type == "Int" else "float"
            
            # Use regex to check for regType assignments
            result_match = RESULT_REGEX.search(text)
            if result_match:
                result_type = result_match.group(1)
                return_type = "int" if result_type == "Int" else "float"
        
        # Return the parameter map and the return type
        return parameter_map, return_type
    except Exception as e:
        print(f"Error analyzing function at {hex(func_addr)}: {e}")
        return {}, "void"

# Helper function to dump a single scrCommandTable_t
def dump_command_table(category, index, table_addr, count):
    commands = []
    for i in range(count):
        entry_addr = table_addr + (i * 8)  # sizeof(scrCommandTable_t) = 8
        
        # Read the pFunc
        p_func = idc.get_wide_dword(entry_addr)

        parameter_count = idc.get_wide_dword(entry_addr + 4)
        
        command_name = f'FUNCTION_{i:04X}'
        
        # Analyze the function for parameters and return type
        parameter_map, return_type = analyze_function(p_func) if p_func else ({}, "void")
        
        # Rename the function at pFunc
        if p_func:
            sanitized_name = sanitize_name(command_name)
            func_name = f"scrCommand_{sanitized_name}"
            idc.set_name(p_func, func_name, idc.SN_NOWARN)
        
        # Generate parameters list from the map
        parameters = []
        for j in range(parameter_count):
            param_type = parameter_map[j] if j in parameter_map else 'int'
            parameters.append({"Type": param_type, "Name": f"param{j+1}", "Description": ""})
        
        # Calculate the index
        calculated_index = (0x1000 * index) + i
        
        # Add command details to the list
        commands.append({
            "Index": f"0x{calculated_index:04X}",
            "ReturnType": return_type,
            "Name": command_name,
            "Description": "" if p_func else 'Null pointer',
            "Parameters": parameters,
        })
    
    return commands

# Main function
def dump(addr, count):
    # Dump the command table
    category = 'Common'
    commands = dump_command_table(category, 0, addr, count)
    
    # Write to a separate JSON file
    try:
        shutil.rmtree(os.path.join(OUTPUT_DIR, category))
    except:
        pass
    os.mkdir(os.path.join(OUTPUT_DIR, category))
    output_file = os.path.join(OUTPUT_DIR, f"{category}/Functions.json")
    with open(output_file, "w") as json_file:
        json.dump(commands, json_file, indent=2)
    
    print(f"Dumped category '{category}' to {output_file}")

def main():
    dump(0x020C65EC, 502)

# Run the script
if __name__ == "__main__":
    main()
