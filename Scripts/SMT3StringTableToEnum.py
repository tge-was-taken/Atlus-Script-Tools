from idaapi import *
import idautils
import idc
import re

def ParseStringTableToEnum( enumName, address, count ):
	
	print '{'
	print '"Name": "%s",' % enumName
	print '"Description": "This enum represents the available skills in battle.",'
	print '"Members": ['

	stringHashSet = set()

	for i in range( 0, count ):
		pString = get_32bit( address + (i * 4) )
		string  = get_ascii_contents( pString, get_max_ascii_length( pString, ASCSTR_C ), ASCSTR_C )

		if ( string ):
			enumValueName = string
			enumValueName = enumValueName.replace( ' ', '' )
			enumValueName = enumValueName.replace( ',', '' )
			enumValueName = enumValueName.replace( '_', '' )
			enumValueName = enumValueName.replace( "'", '' )
			enumValueName = enumValueName.replace( '(', '' )
			enumValueName = enumValueName.replace( ')', '' )
			enumValueName = enumValueName.replace( ':', '' )
			enumValueName = enumValueName.replace( '-', '' )
			enumValueName = enumValueName.replace( '&', 'And' )
			enumValueName = enumValueName.replace( '!', '' )

			if ( enumValueName[0].isdigit() ):
				enumValueName = '_' + enumValueName
		else:
			enumValueName = "Null"

		duplicateEnumValueName = enumValueName
		duplicateCounter = 1
		while ( enumValueName in stringHashSet ):
			enumValueName = '%s%d' % ( duplicateEnumValueName, duplicateCounter )
			duplicateCounter += 1

		stringHashSet.add( enumValueName )

		print '{'
		print '"Name": "%s",' % enumValueName
		print '"Value": %d,' % i
		print '"Description": "Generated from skill name table entry: %s"' % string

		if ( i != count - 1):
			print '},'
		else:
			print '}'

	print ']'
	print '}'
		

# Nocturne
#ParseStringTableToEnum( "BattleSkill", 0x003E83F0, 512 )
ParseStringTableToEnum( "BattleUnit", 0x003E7328, 386 )