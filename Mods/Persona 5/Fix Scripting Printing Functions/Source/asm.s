
.set pIntFormatString, 		0xB6394C
.set pFloatFormatString, 	0xB6397C
.set pStringFormatString, 	0xB63994
.set pNewlineString,		0xB91820
.set pPrintf,				0xAD546C
.set pPutInt,				0xB44B98
.set pPutIntRet,			0x1E9D14
.set pPutFloat,				0xB44BB8
.set pPutFloatRet,			0x1E9D6C
.set pPutString,			0xB44BD8
.set pPutStringRet,			0x1E9D40

.ScriptInterpreter_Comm_PUT_Hook:
# 0x1E9D10
ba		pPutInt

PutInt:
# 0xB44B98
mr		r4, r3
lis 	r3, pIntFormatString@h
addic 	r3, r3, pIntFormatString@l
bla 	pPrintf
lis 	r3, pNewlineString@h
addic 	r3, r3, pNewlineString@l
bla 	pPrintf
ba		pPutIntRet

.ScriptInterpreter_Comm_PUTF_Hook:
# 0x1E9D68
ba		pPutFloat

PutFloat:
# 0xB44BB8
# stfd	f1, 0x70(r1)
# ld	r4, 0x70(r1)
fmr		f2, f1
lis 	r3, pFloatFormatString@h
addic 	r3, r3, pFloatFormatString@l
bla 	pPrintf
lis 	r3, pNewlineString@h
addic 	r3, r3, pNewlineString@l
bla 	pPrintf
ba		pPutFloatRet

.ScriptInterpreter_Comm_PUTS_Hook:
# 0x1E9D3C
ba		pPutString

PutString:
# 0xB44BD8
mr		r4, r3
lis 	r3, pStringFormatString@h
addic 	r3, r3, pStringFormatString@l
bla 	pPrintf
lis 	r3, pNewlineString@h
addic 	r3, r3, pNewlineString@l
bla 	pPrintf
ba		pPutStringRet