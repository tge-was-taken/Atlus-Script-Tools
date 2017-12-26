from idaapi import *
import idautils
import idc

MIPS_JR = 0x03E00008;

def IsBranchToFunctionAddress( address, funcAddress ):
	operandValue = GetOperandValue( address, 0 )
	#print "%04X" % operandValue

	return operandValue == funcAddress

def GetLastImmediateRegisterValue(address, regIndex):
	while True:

		if (GetOperandValue(address, 0) == regIndex):
			mnem = GetMnem(address)

			if (mnem == "li"):
				return GetOperandValue( address, 1 )
			elif (mnem == "move"):
				regIndex = GetOperandValue( address, 1 )
				if ( regIndex == 0 ):
					return 0

				return GetLastImmediateRegisterValue( address - 4, regIndex )
			else:
				return GetLastImmediateRegisterValue( address - 4, regIndex )

		address -= 4
	
def GetFunctionArgument(funcAddress, index):
	return GetLastImmediateRegisterValue(funcAddress + 4, index + 4)

def ParseCOMMTable( address, getIntArgFuncAddress, getFloatArgFuncAddress, getStringArgFuncAddress, setIntRetValueFuncAddress, setFloatRetValueFuncAddress, entryCount ):

	print "["

	for i in range( 0, entryCount ):

		entryAddress = address + ( i * 8 )

		functionAddress = get_32bit( entryAddress )
		parameterCount = get_32bit( entryAddress + 4 )

		functionName = "FUNCTION_%04X" % i
		functionDescription = ""
		functionReturnType = "void"

		# Fill parameter types
		parameterTypes = []
		for j in range( 0, parameterCount ):
			parameterTypes.append( "unk" )

		if ( functionAddress == 0 ):
			functionDescription = "Null pointer"
		else:

			# Traverse function body to infer argument types
			currentInstructionAddress = functionAddress
			a0Register = 0

			while True:
				instruction = get_32bit( currentInstructionAddress )

				# Stop looping when we hit a return instruction
				if ( instruction == MIPS_JR ):
					break;

				# Check if it's a branch to the get int argument function address
				if ( IsBranchToFunctionAddress( currentInstructionAddress, getIntArgFuncAddress ) ):
					parameterIndex = GetFunctionArgument( currentInstructionAddress, 0 )
					if ( parameterIndex >= 0 and parameterIndex < parameterCount ):
						parameterTypes[ parameterIndex ] = "int"

				# Check if it's a branch to the get float argument function address
				if ( IsBranchToFunctionAddress( currentInstructionAddress, getFloatArgFuncAddress ) ):
					parameterIndex = GetFunctionArgument( currentInstructionAddress, 0 )
					if ( parameterIndex >= 0 and parameterIndex < parameterCount ):
						parameterTypes[ parameterIndex ] = "float"

				# Check if it's a branch to the get float argument function address
				if ( IsBranchToFunctionAddress( currentInstructionAddress, getStringArgFuncAddress ) ):
					parameterIndex = GetFunctionArgument( currentInstructionAddress, 0 )
					if ( parameterIndex >= 0 and parameterIndex < parameterCount ):
						parameterTypes[ parameterIndex ] = "string"

				# Check if it's a branch to the set int return value function address
				if ( IsBranchToFunctionAddress( currentInstructionAddress, setIntRetValueFuncAddress ) ):
					functionReturnType = "int"

				# Check if it's a branch to the set float return value function address
				if ( IsBranchToFunctionAddress( currentInstructionAddress, setFloatRetValueFuncAddress ) ):
					functionReturnType = "float"

				currentInstructionAddress += 4
					

		print '    {'
		print '        "Index": "0x%04x",' % i
		print '        "ReturnType": "%s",' % functionReturnType
		print '        "Name": "%s",' % functionName
		print '        "Description": "%s",' % functionDescription
		print '        "Parameters":'
		print '        ['

		for j in range( 0, parameterCount ):

			parameterDescription = ""
			parameterType = parameterTypes[ j ]
			if ( parameterType == "unk" ):
				parameterDescription = "Unknown type; assumed int"
				parameterType = "int"

			parameterName = "param%s" % ( j + 1 )

			print '			{'
			print '				"Type": "%s",' % parameterType
			print '				"Name": "%s",' % parameterName
			print '				"Description": "%s"' % parameterDescription

			if ( j != parameterCount - 1 ):
				print '			},'
			else:
				print '			}'

		print '        ]'

		if ( i != entryCount - 1 ):
			print '    },'
		else:
			print '    }'

	print "]"

	return

# DDS 1
#ParseCOMMTable( 0x0039E388, 0, 0, 0, 544 )

# Nocturne
ParseCOMMTable( 0x0052E350, 0x0010B5C8, 0x0010B690, 0x0010B748, 0x0010B790, 0x0010B7A8, 544 )