from idaapi import *
import idautils
import idc

MIPS_JR = 0x03E00008

def IsBranchToFunctionAddress(address, funcAddress):
    operandValue = idc.get_operand_value(address, 0)
    # print("{:04X}".format(operandValue))
    return operandValue == funcAddress

def GetLastImmediateRegisterValue(address, regIndex):
    while True:
        if idc.get_operand_value(address, 0) == regIndex:
            mnem = idc.print_insn_mnem(address)

            if mnem == "li":
                return idc.get_operand_value(address, 1)
            elif mnem == "move":
                regIndex = idc.get_operand_value(address, 1)
                if regIndex == 0:
                    return 0
                return GetLastImmediateRegisterValue(address - 4, regIndex)
            else:
                return GetLastImmediateRegisterValue(address - 4, regIndex)

        address -= 4

def GetFunctionArgument(funcAddress, index):
    return GetLastImmediateRegisterValue(funcAddress + 4, index + 4)

def ParseCOMMTable(address, getIntArgFuncAddress, getFloatArgFuncAddress, getStringArgFuncAddress, setIntRetValueFuncAddress, setFloatRetValueFuncAddress, entryCount):
    print("[")
    for i in range(entryCount):
        entryAddress = address + (i * 8)

        functionAddress = idc.get_wide_dword(entryAddress)
        parameterCount = idc.get_wide_dword(entryAddress + 4)

        functionName = "FUNCTION_{:04X}".format(i)
        functionDescription = ""
        functionReturnType = "void"

        # Fill parameter types
        parameterTypes = ["unk"] * parameterCount

        if functionAddress == 0:
            functionDescription = "Null pointer"
        else:
            # Traverse function body to infer argument types
            currentInstructionAddress = functionAddress

            while True:
                instruction = idc.get_wide_dword(currentInstructionAddress)

                # Stop looping when we hit a return instruction
                if instruction == MIPS_JR:
                    break

                # Check if it's a branch to the get int argument function address
                if IsBranchToFunctionAddress(currentInstructionAddress, getIntArgFuncAddress):
                    parameterIndex = GetFunctionArgument(currentInstructionAddress, 0)
                    if 0 <= parameterIndex < parameterCount:
                        parameterTypes[parameterIndex] = "int"

                # Check if it's a branch to the get float argument function address
                if IsBranchToFunctionAddress(currentInstructionAddress, getFloatArgFuncAddress):
                    parameterIndex = GetFunctionArgument(currentInstructionAddress, 0)
                    if 0 <= parameterIndex < parameterCount:
                        parameterTypes[parameterIndex] = "float"

                # Check if it's a branch to the get string argument function address
                if IsBranchToFunctionAddress(currentInstructionAddress, getStringArgFuncAddress):
                    parameterIndex = GetFunctionArgument(currentInstructionAddress, 0)
                    if 0 <= parameterIndex < parameterCount:
                        parameterTypes[parameterIndex] = "string"

                # Check if it's a branch to the set int return value function address
                if IsBranchToFunctionAddress(currentInstructionAddress, setIntRetValueFuncAddress):
                    functionReturnType = "int"

                # Check if it's a branch to the set float return value function address
                if IsBranchToFunctionAddress(currentInstructionAddress, setFloatRetValueFuncAddress):
                    functionReturnType = "float"

                currentInstructionAddress += 4

        print("    {")
        print('        "Index": "0x{:04x}",'.format(i))
        print('        "ReturnType": "{}",'.format(functionReturnType))
        print('        "Name": "{}",'.format(functionName))
        print('        "Description": "{}",'.format(functionDescription))
        print('        "Parameters":')
        print("        [")

        for j in range(parameterCount):
            parameterDescription = ""
            parameterType = parameterTypes[j]
            if parameterType == "unk":
                parameterDescription = "Unknown type; assumed int"
                parameterType = "int"

            parameterName = "param{}".format(j + 1)

            print("            {")
            print('                "Type": "{}",'.format(parameterType))
            print('                "Name": "{}",'.format(parameterName))
            print('                "Description": "{}"'.format(parameterDescription))

            if j != parameterCount - 1:
                print("            },")
            else:
                print("            }")

        print("        ]")

        if i != entryCount - 1:
            print("    },")
        else:
            print("    }")

    print("]")

    return

# DDS 1
# ParseCOMMTable(0x0039E388, 0, 0, 0, 544)

# DDS 2
# ParseCOMMTable(0x00411408, 0x0010D650, 0x0010D718, 0x0010D7D0, 0x0010D818, 0x0010D830, 544)

# Raidou 1
# ParseCOMMTable(0x444D88, 0x113CF8, 0x113DC0, 0x113E78, 0x113EC0, 0x113ED8, 592)

ParseCOMMTable(0x004A76E8, 0x00116240, 0x00116308, 0x001163C0, 0x00116408, 0x00116420, 592)

# SMT3
# ParseCOMMTable(0x0052E350, 0x0010B5C8, 0x0010B690, 0x0010B748, 0x0010B790, 0x0010B7A8, 544)
