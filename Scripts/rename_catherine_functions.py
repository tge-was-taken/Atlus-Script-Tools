import idaapi
import idautils
import idc

def rename_function_containing_gamebryoMalloc_calls():
    # Get the address of the gamebryoMalloc function.
    gamebryo_malloc_addr = idc.get_name_ea_simple("gamebryoMalloc")
    if gamebryo_malloc_addr == idc.BADADDR:
        print("gamebryoMalloc not found in the current IDB.")
        return
    
    print(f"gamebryoMalloc found at address: {hex(gamebryo_malloc_addr)}")

    # Iterate over all references to gamebryoMalloc.
    for ref in idautils.CodeRefsTo(gamebryo_malloc_addr, 0):
        print(f"Found a call to gamebryoMalloc at: {hex(ref)}")
        
        # Get the function containing the call.
        func = idaapi.get_func(ref)
        if not func:
            print(f"No containing function found for call at: {hex(ref)}")
            continue
        
        func_start = func.start_ea
        print(f"Call at {hex(ref)} is in function starting at: {hex(func_start)}")
        
        # Traverse the call stack to find the third argument.
        args = []
        max_args = 3  # We only need the 3rd argument.
        current_instr = ref
        
        while len(args) < max_args:
            current_instr = idc.prev_head(current_instr)
            if current_instr == idc.BADADDR:
                print("Reached BADADDR before finding all arguments.")
                break

            disasm = idc.generate_disasm_line(current_instr, 0)
            if disasm is None:
                continue

            # Look for `push` instructions (assuming a typical calling convention).
            if "push" in disasm:
                operand = idc.get_operand_value(current_instr, 0)
                args.append(operand)
        
        # Check if we found 3 arguments.
        if len(args) < 3:
            print(f"Not enough arguments found at call: {hex(ref)}")
            continue

        # The third argument is the last one pushed (reverse the args list).
        third_arg = args[-1]
        
        # If the third argument is a string, get its value.
        third_arg_string = idc.get_strlit_contents(third_arg)
        if third_arg_string:
            function_name = third_arg_string.decode('utf-8')
            print(f"Renaming function at {hex(func_start)} to: {function_name}")
            
            # Rename the containing function.
            idaapi.set_name(func_start, function_name, idaapi.SN_FORCE)
        else:
            print(f"Third argument is not a valid string at call: {hex(ref)}")

rename_function_containing_gamebryoMalloc_calls()
