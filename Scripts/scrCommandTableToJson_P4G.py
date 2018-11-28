from idaapi import *
import idautils
import idc

def ParseCOMMTable( address, entryCount, functionPrefix, baseIndex, getIntArgFuncAddress, getFloatArgFuncAddress, getStringArgFuncAddress, setIntRetValueFuncAddress, setFloatRetValueFuncAddress ):

	print "["

	for i in range( 0, entryCount ):

		entryAddress = address + ( i * 8 )

		functionAddress = get_32bit( entryAddress )
		parameterCount = get_32bit( entryAddress + 4 )

		functionName = functionPrefix + "FUNCTION_%04X" % i
		functionDescription = ""
		functionReturnType = "void"

		# Fill parameter types
		parameterTypes = []
		for j in range( 0, parameterCount ):
			parameterTypes.append( "unk" )

		if ( functionAddress == 0 ):
			functionDescription = "Null pointer"
		else:
			codeFunctionName = get_func_name( functionAddress )
			
			if ( not codeFunctionName.startswith( "sub_" ) ):
				functionDescription = "Code function name: %s" % codeFunctionName
				
			# Traverse function body to infer argument types
			curEa = functionAddress
			endEa = FindFuncEnd( functionAddress )

			while ( curEa < endEa ):
				if ( GetMnem( curEa ) == "BL" ):
					calledFuncEa = GetOperandValue( curEa, 0 )
					
					# Check if it's a branch to the set int return value function address
					if ( calledFuncEa == setIntRetValueFuncAddress ):
						functionReturnType = "int"

					# Check if it's a branch to the set float return value function address
					if ( calledFuncEa == setFloatRetValueFuncAddress ):
						functionReturnType = "float"				
				elif ( GetMnem( curEa ) != "MOVS" ):
					curEa += 1
					continue
				else:
					offset = 2
					if ( GetMnem( curEa + offset ) != "BL" ):
						curEa += offset
						continue
						
					calledFuncEa = GetOperandValue( curEa + offset, 0 )
					
					# Check if it's a branch to the get int argument function address
					if ( calledFuncEa == getIntArgFuncAddress ):
						parameterIndex = GetOperandValue( curEa, 1 )
						if ( parameterIndex >= 0 and parameterIndex < parameterCount ):
							parameterTypes[ parameterIndex ] = "int"

					# Check if it's a branch to the get float argument function address
					if ( calledFuncEa == getFloatArgFuncAddress ):
						parameterIndex = GetOperandValue( curEa, 1 )
						if ( parameterIndex >= 0 and parameterIndex < parameterCount ):
							parameterTypes[ parameterIndex ] = "float"

					# Check if it's a branch to the get float argument function address
					if ( calledFuncEa == getStringArgFuncAddress ):
						parameterIndex = GetOperandValue( curEa, 1 )
						if ( parameterIndex >= 0 and parameterIndex < parameterCount ):
							parameterTypes[ parameterIndex ] = "string"

				curEa += 1
					

		print '    {'
		print '        "Index": "0x%04x",' % ( i + baseIndex )
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

def ParseCOMMTables( address, count, getIntArgFuncAddress, getFloatArgFuncAddress, getStringArgFuncAddress, setIntRetValueFuncAddress, setFloatRetValueFuncAddress ):
	
	functionPrefixes = [ "", "FLD_", "AI_", "EVT_", "CLD_", "UNK_" ]

	for i in range( 0, count ):
		baseIndex = (0x1000 * i)
		tableAddress = get_32bit( address )
		entryCount = get_32bit( address + 4 )
		ParseCOMMTable( tableAddress, entryCount, functionPrefixes[i], baseIndex, getIntArgFuncAddress, getFloatArgFuncAddress, getStringArgFuncAddress, setIntRetValueFuncAddress, setFloatRetValueFuncAddress )
		address += 8
		
		
ParseCOMMTables( 0x81464F34, 6, 0x81010F24, 0x81010FCE, 0x8101107C, 0x810110DE, 0x810110F4 );