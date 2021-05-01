from idaapi import *
import idautils
import idc

MIPS_JR = 0x03E00008


def isBranchToFunctionAddress(address, funcAddress):
    operandValue = idc.get_operand_value(address, 0)
    return operandValue == funcAddress


def getLastImmediateRegisterValue(address, regIndex):
    while True:

        if (idc.get_operand_value(address, 0) == regIndex):
            mnem = idc.print_insn_mnem(address)

            if (mnem == "li"):
                return idc.get_operand_value(address, 1)
            elif (mnem == "move"):
                regIndex = idc.get_operand_value(address, 1)
                if (regIndex == 0):
                    return 0

                return getLastImmediateRegisterValue(address - 4, regIndex)
            else:
                return getLastImmediateRegisterValue(address - 4, regIndex)

        address -= 4


def getFunctionArgument(funcAddress, index):
    return getLastImmediateRegisterValue(funcAddress + 4, index + 4)


def parseCommandTable(address, entryCount, functionPrefix, baseIndex, getIntArgFuncAddress, getFloatArgFuncAddress, getStringArgFuncAddress, setIntRetValueFuncAddress, setFloatRetValueFuncAddress):

    print("[")

    for i in range(0, entryCount):

        entryAddress = address + (i * 8)

        functionAddress = get_32bit(entryAddress)
        parameterCount = get_32bit(entryAddress + 4)

        functionName = functionPrefix + f"FUNCTION_{i:04X}"
        idc.set_name(functionAddress, "scrCommand_" + functionName, SN_CHECK)
        functionDescription = f"Address: 0x{functionAddress:08X}"
        functionReturnType = "void"

        # Fill parameter types
        parameterTypes = []
        for j in range(0, parameterCount):
            parameterTypes.append("unk")

        if (functionAddress == 0):
            functionDescription = "Null pointer"
        else:

            # Traverse function body to infer argument types
            currentInstructionAddress = functionAddress
            a0Register = 0

            while True:
                instruction = get_32bit(currentInstructionAddress)

                # Stop looping when we hit a return instruction
                if (instruction == MIPS_JR):
                    break

                # Check if it's a branch to the get int argument function address
                if (isBranchToFunctionAddress(currentInstructionAddress, getIntArgFuncAddress)):
                    parameterIndex = getFunctionArgument(
                        currentInstructionAddress, 0)
                    if (parameterIndex >= 0 and parameterIndex < parameterCount):
                        parameterTypes[parameterIndex] = "int"

                # Check if it's a branch to the get float argument function address
                if (isBranchToFunctionAddress(currentInstructionAddress, getFloatArgFuncAddress)):
                    parameterIndex = getFunctionArgument(
                        currentInstructionAddress, 0)
                    if (parameterIndex >= 0 and parameterIndex < parameterCount):
                        parameterTypes[parameterIndex] = "float"

                # Check if it's a branch to the get float argument function address
                if (isBranchToFunctionAddress(currentInstructionAddress, getStringArgFuncAddress)):
                    parameterIndex = getFunctionArgument(
                        currentInstructionAddress, 0)
                    if (parameterIndex >= 0 and parameterIndex < parameterCount):
                        parameterTypes[parameterIndex] = "string"

                # Check if it's a branch to the set int return value function address
                if (isBranchToFunctionAddress(currentInstructionAddress, setIntRetValueFuncAddress)):
                    functionReturnType = "int"

                # Check if it's a branch to the set float return value function address
                if (isBranchToFunctionAddress(currentInstructionAddress, setFloatRetValueFuncAddress)):
                    functionReturnType = "float"

                currentInstructionAddress += 4

        print('    {')
        print(f'        "Index": "0x{i + baseIndex:04x}",')
        print(f'        "ReturnType": "{functionReturnType}",')
        print(f'        "Name": "{functionName}",')
        print(f'        "Description": "{functionDescription}",')
        print('        "Parameters":')
        print('        [')

        for j in range(0, parameterCount):

            parameterDescription = ""
            parameterType = parameterTypes[j]
            if (parameterType == "unk"):
                parameterDescription = "Unknown type; assumed int"
                parameterType = "int"

            parameterName = f"param{( j + 1 )}"

            print('			{')
            print(f'				"Type": "{parameterType}",')
            print(f'				"Name": "{parameterName}",')
            print(f'				"Description": "{parameterDescription}"')

            if (j != parameterCount - 1):
                print('			},')
            else:
                print('			}')

        print('        ]')

        if (i != entryCount - 1):
            print('    },')
        else:
            print('    }')

    print("]")

    return


def parseCommandTableList(address, count, getIntArgFuncAddress, getFloatArgFuncAddress, getStringArgFuncAddress, setIntRetValueFuncAddress, setFloatRetValueFuncAddress):

    functionPrefixes = ["", "FLD_", "AI_", "EVT_", "FCL_", "SHD_"]

    for i in range(0, count):
        baseIndex = (0x1000 * i)
        tableAddress = get_32bit(address)
        entryCount = get_32bit(address + 4)
        parseCommandTable(tableAddress, entryCount, functionPrefixes[i], baseIndex, getIntArgFuncAddress,
                       getFloatArgFuncAddress, getStringArgFuncAddress, setIntRetValueFuncAddress, setFloatRetValueFuncAddress)
        address += 8


# P3 JPN NTSC-J
#parseCommandTable( 0x79ED80, 489, "", 0, 0x0034A720, 0x0034A860, 0x0034A9A0, 0x0034AA60, 0x0034AA80 )

# P3 FES NTSC-J
#parseCommandTable( 0x007BAE60, 0x1F6, "", 0, 0x35EC20, 0x35ED60, 0x35EEA0, 0x35EF60, 0x35EF80 )

# P3P ULUS10512
parseCommandTableList(0x08B868B8, 6, 0x08976ED8, 0x08977034, 0x08977188, 0x08977264, 0x08977278)

# P4
#parseCommandTableList( 0x00748530, 4, 0x0029CC00, 0x0029CD50, 0x0029CE90, 0x0029CF50, 0x0029CF70 );
