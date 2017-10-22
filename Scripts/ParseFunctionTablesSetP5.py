from idaapi import *
import idautils
import idc

MAX_RECURSION_DEPTH = 8

FUNCTIONPTR_GET_INT_ARG 			= 0x1F266C
FUNCTIONPTR_GET_FLOAT_ARG 			= 0x1F2768
FUNCTIONPTR_GET_STRING_ARG 			= 0x1F2868
FUNCTIONPTR_GET_MSG_HANDLE_ARG		= 0x1F2954
FUNCTIONPTR_SET_INT_RETURN_VALUE	= 0x1F28D8
FUNCTIONPTR_SET_FLOAT_RETURN_VALUE	= 0x1F28F0

def IsBranch(address):
	if (GetMnem(address) != "b"):
		return False
	
	return True
		
def GetBranchAddress(address):
	return GetOperandValue(address, 0)

def IsBranchToFunctionAddress(address, funcAddress):
	return GetOperandValue(address, 0) == funcAddress

def IsReturn(address):
	return get_32bit(address) == 0x4E800020

def GetLastImmediateRegisterValue(address, regIndex):
	while True:

		if (GetOperandValue(address, 0) == regIndex):
			mnem = GetMnem(address)

			if (mnem == "li"):
				return GetOperandValue(address, 1)
			elif (mnem == "mr"):
				regIndex = GetOperandValue(address, 1)
				return GetLastImmediateRegisterValue(address - 4, regIndex)
			else:
				raise Exception(mnem)

		address -= 4
	
def GetFunctionArgument(funcAddress, index):
	return GetLastImmediateRegisterValue(funcAddress - 4, index + 3)


def ParseFunctionTable(address, count, index):
	
	for i in range(0, count):
	
		functionOPDAddress = get_32bit(address)
		address += 4
		
		functionParameterCount = get_32bit(address)
		address += 4
		
		functionNameAddress = get_32bit(address)
		address += 4
		
		# retrieve function name
		functionName = get_ascii_contents(functionNameAddress, get_max_ascii_length(functionNameAddress, ASCSTR_C), ASCSTR_C) 

		#MakeName(functionOPDAddress, "ScriptInterpreter::ExecuteCommFunc_" + functionName)
		
		#print functionName
		isNull = False
		
		# set up default values for types
		argTypes = []
		argNames = []
		retType = "unk"
		
		for j in range(0, functionParameterCount):
			argTypes.append("unk")
			argNames.append("param" + str(j + 1))
		
		if (functionOPDAddress):
				
			# retrieve function address
			functionAddress = get_32bit(functionOPDAddress)
			functionStartAddress = functionAddress
			functionEndAddress = FindFuncEnd(functionAddress)

			#MakeName(functionAddress, ".ScriptInterpreter::ExecuteCommFunc_" + functionName)		
			
			# retrieve function return & argument types
			retType = "void"
			
			isDone = False
			argIndex = -1
			branchDepth = -1
			startAddressStack = [ functionStartAddress ]
			endAddressStack = [ functionEndAddress ]
			returnAddressStack = []

			while not isDone:
				instruction = get_32bit(functionAddress)
				
				if (not IsBranch(functionAddress)):
					functionAddress += 4
					continue
				
				if (IsReturn(functionAddress)):
					#print "exit branch at %04x" % functionAddress
					if (branchDepth > -1):				
						functionAddress = returnAddressStack.pop()
						functionStartAddress = startAddressStack.pop()
						functionEndAddress = endAddressStack.pop()
						branchDepth -= 1
						continue
					else:
						isDone = True
					
				branchAddress = GetBranchAddress(functionAddress)
					
				if (branchAddress == FUNCTIONPTR_GET_INT_ARG):
					argIndex = GetFunctionArgument(functionAddress, 0)
					if (not argIndex < len(argTypes)):
						argTypes.append("int")
						argNames.append("param" + str(argIndex + 1))
						functionParameterCount += 1
					else:
						argTypes[argIndex] = "int"
					
				elif (branchAddress == FUNCTIONPTR_GET_FLOAT_ARG):
					argIndex = GetFunctionArgument(functionAddress, 0)
					if (not argIndex < len(argTypes)):
						argTypes.append("float")
						argNames.append("param" + str(argIndex + 1))
						functionParameterCount += 1
					else:
						argTypes[argIndex] = "float"
					
				elif (branchAddress == FUNCTIONPTR_GET_STRING_ARG):
					argIndex = GetFunctionArgument(functionAddress, 0)
					if (not argIndex < len(argTypes)):
						argTypes.append("string")
						argNames.append("param" + str(argIndex + 1))
						functionParameterCount += 1
					else:
						argTypes[argIndex] = "string"
			
				#elif (branchAddress == FUNCTIONPTR_GET_MSG_HANDLE_ARG):
				#	argIndex = GetFunctionArgument(functionAddress, 0)
				#	if (not argIndex < len(argTypes)):
				#		argTypes.append("msg")
				#		argNames.append("param" + str(argIndex))
				#		functionParameterCount += 1
				#	else:
				#		argTypes[argIndex] = "msg"
					
				elif (branchAddress == FUNCTIONPTR_SET_INT_RETURN_VALUE):
					retType = "int"
					
				elif (branchAddress == FUNCTIONPTR_SET_FLOAT_RETURN_VALUE):
					retType = "float"
					
				elif ((instruction != 0x4E800421) and (instruction != 0x4E800420) and (branchAddress < functionStartAddress or branchAddress >= functionEndAddress) and (branchDepth < MAX_RECURSION_DEPTH - 1) and (branchAddress not in startAddressStack)):
					#print "enter branch at %04x" % functionAddress
					returnAddressStack.append(functionAddress + 4)
					startAddressStack.append(functionStartAddress)
					endAddressStack.append(functionEndAddress)
					functionAddress = branchAddress
					functionStartAddress = branchAddress
					functionEndAddress = FindFuncEnd(branchAddress)
					branchDepth += 1
					continue
					
				functionAddress += 4

				# no return functions
				if (functionAddress >= functionEndAddress):
					functionAddress = returnAddressStack.pop()
					functionStartAddress = startAddressStack.pop()
					functionEndAddress = endAddressStack.pop()
					branchDepth -= 1
					continue
		
			else:			
				isNull = True

		# retrieve function id
		functionID = i + (0x1000 * index)
			
		# create formatted string for function definition
		functionArgsString = ""
		for j in range(0, functionParameterCount):
		
			functionArgsString += argTypes[j] + " " + argNames[j]
				
			if (j != functionParameterCount - 1):
				functionArgsString += ", "

		#print "function(0x%04x) %s %s(%s);" % (functionID, retType, functionName, functionArgsString)

		functionDescription = ""
		if retType == "unk":
			functionDescription = "Null function pointer."
			retType = "void"

		print '    {'
		print '        "Index": "0x%04x",' % functionID
		print '        "ReturnType": "%s",' % retType
		print '        "Name": "%s",' % functionName
		print '        "Description": "%s",' % functionDescription
		print '        "Parameters":'
		print '        ['

		for j in range( 0, functionParameterCount ):

			parameterDescription = ""
			if argTypes[j] == "unk":
				parameterDescription = "Unknown type; assumed int."
				argTypes[j] = "int"

			print '			{'
			print '				"Type": "%s",' % argTypes[j]
			print '				"Name": "%s",' % argNames[j]
			print '				"Description": "%s"' % parameterDescription

			if ( j != functionParameterCount - 1 ):
				print '			},'
			else:
				print '			}'

		print '        ]'

		if ( i != count - 1 ):
			print '    },'
		else:
			print '    }'
	
	return
	
def ParseFunctionTableSet(address, count):
	
	print "["

	for i in range(0, count):
	
		functionTableAddress = get_32bit(address)
		address += 4
		
		functionTableEntryCount = get_32bit(address)
		address += 4
		
		ParseFunctionTable(functionTableAddress, functionTableEntryCount, i)

	print "]"
		
	return
	
ParseFunctionTableSet(0xB63660, 6)
