from idaapi import *
import idautils
import idc

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
			#MakeName(functionOPDAddress, "script_Function_" + functionName + "_OPD")	
		
			# retrieve function address
			functionAddress = get_32bit(functionOPDAddress)
			functionStartAddress = functionAddress
			functionEndAddress = FindFuncEnd(functionAddress)
			
			#MakeName(functionAddress, "script_Function_" + functionName)
			
			# retrieve function return & argument types
			retType = "void"
			
			prevFunctionAddress = 0
			isDone = False
			isInBranch = False
			argIndex = -1

			while not isDone:
				instruction = get_32bit(functionAddress)
				
				if (not GetIsPPCBranch(functionAddress)):
					functionAddress += 4
					continue
				
				if (GetIsPPCBranchLinkReturn(functionAddress)):
					if (isInBranch):
						functionAddress = prevFunctionAddress
						isInBranch = False
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

				elif (branchAddress == cGetFunctionMessageHandleArgument):
					argIndex += 1

					if (not argIndex < len(argTypes)):
						argTypes.append("int")
						argNames.append("messageHandle")
						functionArgumentCount += 1
					else:
						argTypes[argIndex] = "int"
						argNames[argIndex] = "messageHandle"
					
				elif (branchAddress == cSetFunctionIntReturnValueFuncAddr):
					retType = "int"
					
				elif (branchAddress == cSetFunctionFloatReturnValueFuncAddr):
					retType = "float"
					
				elif (branchAddress < functionStartAddress or branchAddress >= functionEndAddress):
					if (not isInBranch):
						prevFunctionAddress = functionAddress + 4
						functionAddress = branchAddress
						isInBranch = True
					
				functionAddress += 4
		
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

		print "0x%04x %s %s(%s)" % (functionID, retType, functionName, functionArgsString)
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
