from idaapi import *
import idautils
import idc

cMaxRecursionDepth = 4
cGetFunctionIntArgumentFuncAddr 		= 0x1F266C
cGetFunctionFloatArgumentFuncAddr 		= 0x1F2768
cGetFunctionStringArgumentFuncAddr 		= 0x1F2868
cGetFunctionMessageHandleArgument		= 0x1F2954
cSetFunctionIntReturnValueFuncAddr		= 0x1F28D8
cSetFunctionFloatReturnValueFuncAddr 	= 0x1F28F0

def GetIsPPCBranch(address):
	if (GetMnem(address) != "b"):
		return False
	
	return True
		
def GetPPCBranchAddress(address):
	return GetOperandValue(address, 0)

def GetIsPPCBranchLinkToFuncAddress(address, funcAddress):
	return GetOperandValue(address, 0) == funcAddress

def GetIsPPCBranchLinkReturn(address):
	return get_32bit(address) == 0x4E800020

def GetPPCRegLastKnownValue(address, regIndex):
	while True:

		if (GetOperandValue(address, 0) == regIndex):
			mnem = GetMnem(address)
			#print mnem
			if (mnem == "li"):
				return GetOperandValue(address, 1)
			elif (mnem == "mr"):
				regIndex = GetOperandValue(address, 1)
				return GetPPCRegLastKnownValue(address - 4, regIndex)
			else:
				raise Exception(mnem)

		address -= 4
	
def GetPPCFuncArgument(funcAddress, index):
	return GetPPCRegLastKnownValue(funcAddress - 4, index + 3)


def ParseFunctionTable(address, count, index):
	
	for i in range(0, count):
	
		functionOPDAddress = get_32bit(address)
		address += 4
		
		functionArgumentCount = get_32bit(address)
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
		retType = "null"
		
		for j in range(0, functionArgumentCount):
			argTypes.append("unk")
			argNames.append("arg" + str(j))
		
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
				
				if (not GetIsPPCBranch(functionAddress)):
					functionAddress += 4
					continue
				
				if (GetIsPPCBranchLinkReturn(functionAddress)):
					#print "exit branch at %04x" % functionAddress
					if (branchDepth > -1):				
						functionAddress = returnAddressStack.pop()
						functionStartAddress = startAddressStack.pop()
						functionEndAddress = endAddressStack.pop()
						branchDepth -= 1
						continue
					else:
						isDone = True
					
				branchAddress = GetPPCBranchAddress(functionAddress)
					
				if (branchAddress == cGetFunctionIntArgumentFuncAddr):
					argIndex = GetPPCFuncArgument(functionAddress, 0)
					if (not argIndex < len(argTypes)):
						argTypes.append("int")
						argNames.append("arg" + str(argIndex))
						functionArgumentCount += 1
					else:
						argTypes[argIndex] = "int"
					
				elif (branchAddress == cGetFunctionFloatArgumentFuncAddr):
					argIndex = GetPPCFuncArgument(functionAddress, 0)
					if (not argIndex < len(argTypes)):
						argTypes.append("float")
						argNames.append("arg" + str(argIndex))
						functionArgumentCount += 1
					else:
						argTypes[argIndex] = "float"
					
				elif (branchAddress == cGetFunctionStringArgumentFuncAddr):
					argIndex = GetPPCFuncArgument(functionAddress, 0)
					if (not argIndex < len(argTypes)):
						argTypes.append("string")
						argNames.append("arg" + str(argIndex))
						functionArgumentCount += 1
					else:
						argTypes[argIndex] = "string"
					
				elif (branchAddress == cSetFunctionIntReturnValueFuncAddr):
					retType = "int"
					
				elif (branchAddress == cSetFunctionFloatReturnValueFuncAddr):
					retType = "float"
					
				elif ((instruction != 0x4E800421) and (instruction != 0x4E800420) and (branchAddress < functionStartAddress or branchAddress >= functionEndAddress) and (branchDepth < cMaxRecursionDepth - 1) and (branchAddress not in startAddressStack)):
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
		for j in range(0, functionArgumentCount):
		
			functionArgsString += argTypes[j] + " " + argNames[j]
				
			if (j != functionArgumentCount - 1):
				functionArgsString += ", "

		print "%04x %s %s(%s);" % (functionID, retType, functionName, functionArgsString)
		#print "%d %s %s(%s)" % (functionID, retType, functionName, functionArgsString)
	
	return
	
def ParseFunctionTableSet(address, count):
	
	for i in range(0, count):
	
		functionTableAddress = get_32bit(address)
		address += 4
		
		functionTableEntryCount = get_32bit(address)
		address += 4
		
		ParseFunctionTable(functionTableAddress, functionTableEntryCount, i)
		
	return
	
ParseFunctionTableSet(0xB63660, 6)
