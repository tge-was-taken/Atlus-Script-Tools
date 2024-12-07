from idaapi import *
import idautils
import idc
import re

def ParseStringTableToEnum(enumName, address, count):
    print('{')
    print('"Name": "{}",'.format(enumName))
    print('"Description": "This enum represents the available skills in battle.",')
    print('"Members": [')

    stringHashSet = set()

    for i in range(count):
        pString = idc.get_wide_dword(address + (i * 4))
        string = idc.get_strlit_contents(pString, -1, STRTYPE_C)

        if string:
            string = string.decode('utf-8')  # Decode bytes to string if needed
            enumValueName = string
            # Remove or replace invalid characters for enum names
            enumValueName = enumValueName.replace(' ', '')
            enumValueName = enumValueName.replace(',', '')
            enumValueName = enumValueName.replace('_', '')
            enumValueName = enumValueName.replace("'", '')
            enumValueName = enumValueName.replace('(', '')
            enumValueName = enumValueName.replace(')', '')
            enumValueName = enumValueName.replace(':', '')
            enumValueName = enumValueName.replace('-', '')
            enumValueName = enumValueName.replace('&', 'And')
            enumValueName = enumValueName.replace('!', '')

            if enumValueName[0].isdigit():
                enumValueName = '_' + enumValueName
        else:
            enumValueName = "Null"

        duplicateEnumValueName = enumValueName
        duplicateCounter = 1
        while enumValueName in stringHashSet:
            enumValueName = '{}{}'.format(duplicateEnumValueName, duplicateCounter)
            duplicateCounter += 1

        stringHashSet.add(enumValueName)

        print('    {')
        print('        "Name": "{}",'.format(enumValueName))
        print('        "Value": {},'.format(i))
        print('        "Description": "Generated from skill name table entry: {}"'.format(string))

        if i != count - 1:
            print('    },')
        else:
            print('    }')

    print(']')
    print('}')

# Example usage
# SMT3
# ParseStringTableToEnum("BattleSkill", 0x003E83F0, 512)
ParseStringTableToEnum("BattleUnit", 0x003E7328, 386)
