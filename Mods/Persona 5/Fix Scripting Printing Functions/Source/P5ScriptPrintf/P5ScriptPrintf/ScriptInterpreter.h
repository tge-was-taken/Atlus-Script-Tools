#pragma once

#include <types.h>

struct __attribute__ ((packed)) ScriptCOMMFuncTableEntry_t
{
	/* 0x00 */ OPD_t* pFunc;
	/* 0x04 */ uint32_t numArgs;
	/* 0x08 */ uint8_t* symbol;

};

struct __attribute__ ((packed)) ScriptCOMMFuncTable_t
{
	/* 0x00 */ ScriptCOMMFuncTableEntry_t* pTable;
	/* 0x04 */ uint32_t numEntries;
};

union __attribute__ ((packed)) ScriptInstruction_t
{
	struct
	{
		/* 0x00 */ uint16_t opcode;
		/* 0x02 */ uint16_t operand16;
	};

	/* 0x00 */ uint32_t operand32;
	/* 0x00 */ float operandf;

};

struct __attribute__ ((packed)) ScriptHeader_t
{
	/* 0x00 */ uint16_t type;
	/* 0x02 */ uint16_t userId;
	/* 0x04 */ uint32_t size;
	/* 0x08 */ uint32_t magic;
	/* 0x0C */ uint32_t field0c;
	/* 0x10 */ uint32_t numSections;
	/* 0x14 */ uint16_t numLocalIntVars;
	/* 0x16 */ uint16_t numLocalFloatVars;
	/* 0x18 */ uint16_t endianness;
	/* 0x1A */ uint16_t field1a;

};

struct __attribute__ ((packed)) ScriptSegmentTableEntry_t
{
	/* 0x00 */ uint32_t id;
	/* 0x04 */ uint32_t elementSize;
	/* 0x08 */ uint32_t numElements;
	/* 0x0C */ void* pData;

};

struct __attribute__ ((packed)) ScriptLabel_t
{
	/* 0x00 */ uint8_t name[40];
	/* 0x28 */ uint32_t instructionIndex;
	/* 0x2C */ uint32_t field2c;

};

struct __attribute__ ((packed)) MessageScriptHeader_t
{
	/* 0x00 */ uint32_t field00;
	/* 0x04 */ uint32_t field04;
	/* 0x08 */ uint32_t magic;
	/* 0x0C */ uint32_t flag;
	/* 0x10 */ uint8_t* pRelocTable;
	/* 0x14 */ uint32_t relocTableSize;
	/* 0x18 */ uint32_t numEntries; 
	/* 0x1C */ uint16_t relocFlag;
	/* 0x1E */ uint16_t field1E;

};

struct __attribute__ ((packed)) MessageScriptSubHeader_t
{
	/* 0x00 */ uint8_t* pRelocTable;
	/* 0x08 */ uint32_t field08; // usually 0, if not, calculates value ((start of sub header + field08) + 8)

};

struct __attribute__ ((packed)) MessageScriptDialogue
{
	/* 0x00 */ uint8_t name[12];
	/* 0x0C */ uint32_t* pField0C; // if not 0, points to 0x450 bytes of data
	/* 0x10 */ uint32_t pField10; // if pField10 != 0, pField0C points to another data structure
	/* */

};

struct __attribute__ ((packed)) MessageScriptEntry_t
{
	/* 0x00 */ uint16_t field00;
	/* 0x04 */ uint32_t* pData;

};

struct __attribute__ ((packed)) ScriptInterpreter
{
    // Fields
	/* 0x0000 */ uint8_t mProcedureName[40];
	/* 0x0028 */ uint32_t mInstructionIndex;			
	/* 0x002c */ uint32_t mNumStackValues; 
	/* 0x0030 */ uint8_t mStackValueTypes[47];
	/* 0x005F */ uint8_t mREGValueType;
	/* 0x0060 */ uint32_t mStackValues[47];
	/* 0x011c */ uint32_t mREGValue;
	/* 0x0120 */ ScriptHeader_t* mpHeader;
	/* 0x0124 */ ScriptSegmentTableEntry_t* mpSegmentTable;
	/* 0x0128 */ ScriptLabel_t* mpProcedureLabels;
	/* 0x012C */ ScriptLabel_t* mpJumpLabels;
	/* 0x0130 */ ScriptInstruction_t* mpInstructions;
	/* 0x0134 */ MessageScriptHeader_t* mpMessageScriptHeader;
	/* 0x0138 */ uint8_t* mpStringTable;
	/* 0x013C */ uint32_t mProcedureIndex;
	/* 0x0140 */ uint32_t mpMessageScript;
	/* 0x0144 */ uint32_t field144;
	/* 0x0148 */ uint32_t field148;
	/* 0x014C */ uint32_t field14c;
	/* 0x0150 */ uint32_t field150; // ScriptHeader_t*
	/* 0x0154 */ uint32_t* mpLocalIntVariablePool;
	/* 0x0158 */ float* mpLocalFloatVariablePool;
	/* 0x015C */ uint32_t field15c;
	/* 0x0160 */ uint32_t pStaticInstance2;
	/* 0x0164 */ uint32_t pInstance1;
	/* 0x0168 */ uint32_t field168;
	/* 0x016C */ uint32_t field16C;
};

