
// types
#include <stdint.h>

// memset
// strcpy
#include <cstring> 

static void* memzero(void* _Dst, size_t _Size)
{
	return memset(_Dst, 0, _Size);
}

typedef struct
{
	/* 0x00 */ void* pFunc;
	/* 0x04 */ uint32_t toc;

} OPD_t;

typedef struct
{
	/* 0x00 */ OPD_t* pFunc;
	/* 0x04 */ uint32_t numArgs;
	/* 0x08 */ uint8_t* symbol;

} ScriptCOMMFuncTableEntry_t;

typedef struct
{
	/* 0x00 */ ScriptCOMMFuncTableEntry_t* pTable;
	/* 0x04 */ uint32_t numEntries;

} ScriptCOMMFuncTable_t;

typedef union
{
	struct
	{
		/* 0x00 */ uint16_t opcode;
		/* 0x02 */ uint16_t operand16;
	};

	/* 0x00 */ uint32_t operand32;
	/* 0x00 */ float operandf;

} ScriptInstruction_t;

typedef struct
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

} ScriptHeader_t;

typedef struct
{
	/* 0x00 */ uint32_t id;
	/* 0x04 */ uint32_t elementSize;
	/* 0x08 */ uint32_t numElements;
	/* 0x0C */ void* pData;

} ScriptSegmentTableEntry_t;

typedef struct
{
	/* 0x00 */ uint8_t name[40];
	/* 0x28 */ uint32_t instructionIndex;
	/* 0x2C */ uint32_t field2c;

} ScriptLabel_t;

typedef struct 
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

} MessageScriptHeader_t;

typedef struct 
{
	/* 0x00 */ uint8_t* pRelocTable;
	/* 0x08 */ uint32_t field08; // usually 0, if not, calculates value ((start of sub header + field08) + 8)

} MessageScriptSubHeader_t;

typedef struct 
{
	/* 0x00 */ uint8_t name[12];
	/* 0x0C */ uint32_t* pField0C; // if not 0, points to 0x450 bytes of data
	/* 0x10 */ uint32_t pField10; // if pField10 != 0, pField0C points to another data structure
	/* */

} MessageScriptDialogue;

typedef struct
{
	/* 0x00 */ uint16_t field00;
	/* 0x04 */ uint32_t* pData;

} MessageScriptEntry_t;

void MessageScript::RelocateEntryHeaders(MessageScriptHeader_t* header)
{
	if (header->relocFlag)
		return;

	uint32_t* pEntryBase = header + sizeof(MessageScriptHeader_t);
	uint8_t* pRelocTable = header + header->pRelocTable;

	uint32_t* pCurAddress = pEntryBase;
	uint8_t* pRelocEntry = pRelocTable;
	uint32_t nextAddressOffset = 0;

	while (pRelocTable - pRelocEntry <= header->relocTableSize)
	{
		uint8_t code = *pRelocEntry++;

		if (code & 1)
		{
			if (code & 2)
			{
				if (code & 4)
				{
					uint8_t numLoop = (code >> 3) + 2;

					if (numLoop >= 0)
					{
						for (size_t i = 0; i < numLoop; i++)
						{
							pCurAddress++;
							*pCurAddress += pCurAddress - pEntryBase;
						}
					}
				}
				else
				{
					nextAddressOffset = (nextAddressOffset & 0xFFFF00FF) | ((*pRelocEntry++ << 8) & 0xFF00);
					nextAddressOffset = (nextAddressOffset & 0xFF00FFFF) | ((*pRelocEntry++ << 16) & 0xFF0000);
					nextAddressOffset >>= 3;
				}
			}
			else
			{
				nextAddressOffset = (nextAddressOffset & ~0xFFFF00FF) | ((*pRelocEntry++ << 8) & 0xFF00);
				nextAddressOffset >>= 2;
			}
		}
		else
		{
			nextAddressOffset >>= 1;
		}

		pCurAddress += (nextAddressOffset * sizeof(uint32_t));
		*pCurAddress += pCurAddress - pEntryBase;
	}

	header->relocFlag = 1;
}

class ScriptInterpreter
{
public:

	// Static members
	static ScriptInterpreter* spInstance;
	static OPD_t* spOpcodeFuncTable[35];

	static ScriptCOMMFuncTable_t spScriptCOMMFuncTables[6] = 
	{
		{ nullptr, 0x175 },
		{ nullptr, 0x336 },
		{ nullptr, 0x19b },
		{ nullptr, 0x97 },
		{ nullptr, 0x71 },
		{ nullptr, 0x08 },
	};

	static uint32_t* spStaticIntVariablePool;
	static uint32_t* spStaticFloatVariablePool;

	// Static functions
	static ScriptInterpreter* Create(ScriptHeader_t* pScriptHeader, uint32_t procedureIndex);
	static ScriptInterpreter* Create(ScriptHeader_t* pScriptHeader, ScriptSegmentTableEntry_t* pSegmentTable, ScriptLabel_t* pProcedureLabels, ScriptLabel_t* pJumpLabels, ScriptInstruction_t* pInstructions, MessageScriptHeader_t* pMessageScriptHeader, uint8_t* pStringTable, uint32_t procedureIndex);
	static OPD_t* GetCOMMFuncPtr(uint16_t funcId);
	static uint32_t GetCOMMFuncNumArgs(uint16_t funcId);

	static uint32_t ExecuteInstruction_PUSHI(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_PUSHF(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_PUSHIX(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_PUSHIF(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_PUSHREG(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_POPIX(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_POPFX(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_PROC(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_COMM(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_END(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_JUMP(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_CALL(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_RUN(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_GOTO(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_ADD(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_SUB(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_MUL(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_DIV(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_MINUS(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_NOT(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_OR(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_AND(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_EQ(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_NEQ(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_S(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_L(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_SE(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_LE(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_IF(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_PUSHIS(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_PUSHLIX(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_PUSHLFX(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_POPLIX(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_POPLFX(ScriptInterpreter* instance);
	static uint32_t ExecuteInstruction_PUSHSTR(ScriptInterpreter* instance);

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

	// Functions
	uint32_t TraceInstruction();
	uint32_t TraceInstructionResult(uint32_t traceLength, uint32_t instructionResult);
	uint32_t Execute();
	uint32_t PopIntValue();
	float PopFloatValue();
};

// Instance function definitions
uint32_t ScriptInterpreter::Execute()
{
	while (true)
	{
		uint16_t opcode = this->mpInstructions[this->mInstructionIndex]->opcode;

		if ((this->mpScript->endianness & 1) != 0)
		{
			r3 = (opcode << 8) & 0xFFFF00;
			r3 = (r3 & ~0xFF) | ((opcode >> 8) & 0xFF);
			opcode = r3;
		}

		uint32_t traceLength = this->TraceInstruction();
		uint32_t interpRes = ScriptInterpreter::spOpcodeFuncTable[opcode]->pFunc();
		this->TraceInstructionResult(traceLength, instructionResult);

		switch (switch_on)
		{
		case 0:
			this->field148 = 0;
			return 2;
		case 1:
			this->field148 = 0;
			continue;
		case 2:
			this->field148++;
			this->field144++;
			return 1;
		default:
			continue;
		}
	}
};

uint32_t ScriptInterpreter::PopIntValue()
{
	this->mNumStackValues--;

	uint8_t type = this->mStackValueTypes[this->mNumStackValues];
	uint32_t value = this->mStackValues[this->mNumStackValues];

	switch (type)
	{
	case 7:
		return value;
	case 4:
		return value;
	case 3:
		return (uint32_t)ScriptInterpreter::spStaticFloatVariablePool[value];
	case 2:
		return ScriptInterpreter::spStaticIntVariablePool[value];
	case 1:
		return (uint32_t)value;
	case 0:
		return value;
	default:
		return 0;
	}
};

// Static function definitions
static ScriptInterpreter* ScriptInterpreter::Create(ScriptHeader_t* pScriptHeader, uint32_t procedureIndex)
{
	if (ScriptInterpreter::MaybeSwapEndianness(pScriptHeader) == 0)
		return 0;

	if (pScriptHeader->numSections == 0)
		return 0;

	ScriptSegmentTableEntry_t* pSegmentTable = pScriptHeader + 0x20;
	ScriptSegmentTableEntry_t* pSegmentTableEntry = pSegmentTable;

	ScriptLabel_t* pProcedureLabels = nullptr;
	ScriptLabel_t* pJumpLabels = nullptr;
	ScriptInstruction_t* pInstructions = nullptr;
	MessageScriptHeader_t* pMessageScriptHeader = nullptr;
	uint8_t* pStringTable = nullptr;

	for (uint32_t i = 0; i < pScriptHeader->numSections; i++, pSegmentTableEntry++)
	{
		switch (pSegmentTableEntry->id)
		{
		case 0:
			pProcedureLabels = pScriptHeader + pSegmentTableEntry->pData;
			break;

		case 1:
			pJumpLabels = pScriptHeader + pSegmentTableEntry->pData;
			break;

		case 2:
			pInstructions = pScriptHeader + pSegmentTableEntry->pData;
			break;

		case 3:
			if (pSegmentTableEntry->numElements != 0)
				pMessageScriptHeader = pScriptHeader + pSegmentTableEntry->pData;
			break;

		case 4:
			pStringTable = pScriptHeader + pSegmentTableEntry->pData;
			break;
		}
	}

	return new ScriptInterpreter(pScriptHeader, pProcedureLabels, pJumpLabels, pInstructions, pMessageScriptHeader, pStringTable, pSegmentTable, procedureIndex);
};

static ScriptInterpreter* ScriptInterpreter::Create(ScriptHeader_t* pScriptHeader, ScriptSegmentTableEntry_t* pSegmentTable, ScriptLabel_t* pProcedureLabels, ScriptLabel_t* pJumpLabels, ScriptInstruction_t* pInstructions, MessageScriptHeader_t* pMessageScriptHeader, uint8_t* pStringTable, uint32_t procedureIndex)
{
	if (pScriptHeader == nullptr || pSegmentTable == nullptr || pProcedureLabels == nullptr || pInstructions == nullptr || procedureIndex < 0 || procedureIndex >= pSegmentTable->numElements)
		return 0;

	ScriptInterpreter* pScriptInterpreter = (ScriptInterpreter*)malloc(sizeof(ScriptInterpreter));

	if (pScriptInterpreter == nullptr)
		return 0;

	memzero(pScriptInterpreter, sizeof(ScriptInterpreter));

	strcpy(pProcedureLabels[procedureIndex].name, pScriptInterpreter->mProcedureName);

	uint8_t* stackValueTypes = pScriptInterpreter.mStackValueTypes;
	uint32_t* stackValues = pScriptInterpreter.mStackValues;
	pScriptInterpreter->mNumStackValues = 0;
	pScriptInterpreter->mInstructionIndex = pProcedureLabels[procedureIndex].instructionIndex;

	for (size_t i = 0; i < 0x30; i++)
	{
		*stackValueTypes = 0;
		*stackValues = 0;

		stackValueTypes++;
		stackValues++;
	}

	pScriptInterpreter->mpHeader = pScriptHeader;
	pScriptInterpreter->mpSegmentTable = pSegmentTable;
	pScriptInterpreter->mpProcedureLabels = pProcedureLabels;
	pScriptInterpreter->mpJumpLabels = pJumpLabels;
	pScriptInterpreter->mpInstructions = pInstructions;
	pScriptInterpreter->mpMessageScriptHeader = pMessageScriptHeader;
	pScriptInterpreter->mpStringTable = pStringTable;
	pScriptInterpreter->mProcedureIndex = procedureIndex;
	pScriptInterpreter->mpMessageScript = -1;
	pScriptInterpreter->field144 = nullptr;
	pScriptInterpreter->field148 = nullptr;
	pScriptInterpreter->field14C = nullptr;
	pScriptInterpreter->field150 = nullptr;
	pScriptInterpreter->mpLocalIntVariablePool = nullptr;
	pScriptInterpreter->mpLocalFloatVariablePool = nullptr;
	pScriptInterpreter->field15C = nullptr;
	pScriptInterpreter->pStaticInstance2 = nullptr;
	pScriptInterpreter->pInstance1 = nullptr;
	pScriptInterpreter->field168 = nullptr;
	pScriptInterpreter->field16C = nullptr;

	if (pScriptHeader->numLocalIntVars != 0)
	{
		uint32_t localIntVariablePoolSize = pScriptHeader->numLocalIntVars * sizeof(uint32_t);

		uint32_t* pLocalIntVariablePool = (uint32_t*)malloc(localIntVariablePoolSize);
		pScriptInterpreter->mpLocalIntVariablePool = pLocalFloatVariablePool;

		if (pLocalIntVariablePool != nullptr)
		{
			memzero(pLocalIntVariablePool, localIntVariablePoolSize);
		}
	}

	if (pScriptHeader->numLocalFloatVars != 0)
	{
		uint32_t localFloatVariablePoolSize = pScriptHeader->numLocalFloatVars * sizeof(float);

		float* pLocalFloatVariablePool = (float*)malloc(localFloatVariablePoolSize);
		pScriptInterpreter->mpLocalFloatVariablePool = pLocalFloatVariablePool;

		if (pLocalFloatVariablePool != nullptr)
		{
			memzero(pLocalFloatVariablePool, localFloatVariablePoolSize);
		}
	}

	if (pMessageScriptHeader != 0)
	{
		pScriptInterpreter->mpMessageScript = MessageScript::LoadFromMemory(pMessageScriptHeader);
	}

	if (ScriptInterpreter::spInstance2 != 0)
	{
		pScriptInterpreter->pStaticInstance2 = ScriptInterpreter::spInstance2;
		ScriptInterpreter::spInstance2 = pScriptInterpreter;
		ScriptInterpreter::spInstance2->field164 = pScriptInterpreter;
		pScriptInterpreter->pInstance1 = 0;
	}
	else
	{
		ScriptInterpreter::spInstance3 = pScriptInterpreter;
		ScriptInterpreter::spInstance2 = pScriptInterpreter;
		pScriptInterpreter->pStaticInstance2 = 0;
		pScriptInterpreter->pInstance1 = 0;
	}

	dword_D59BF0->field00++;

	return pScriptInterpreter;
};

static uint32_t ScriptInterpreter::MaybeSwapEndianness(ScriptHeader_t* script)
{
	if (script->magic > 0x30574C46)
	{
		if (script->magic != 0x464C5730)
		{
			return 0;
		}
	}
	else
	{
		if (script->magic <= 0x30574C45)
		{
			return 0;
		}
	}

	ScriptInterpreter::SwapEndianness(script);
};

static OPD_t* ScriptInterpreter::GetCOMMFuncPtr(uint16_t funcId)
{
	uint16_t funcIdx = funcId & 0xFFF;
	uint8_t funcTableIdx = (funcId >> 12) & 0xF;
	ScriptCOMMFuncTableEntry_t* pFuncTableEntry = nullptr;

	if (funcTableIdx < 6)
	{
		uint32_t r4 = (funcId >> 9) & 0x78;
		if (funcIdx >= ScriptInterpreter::spScriptCOMMFuncTables[r4].numEntries)
			return pFuncTableEntry->pFunc;

		pFuncTableEntry = ScriptInterpreter::spScriptCOMMFuncTables[r4].pTable[funcIdx];
	}

	return pFuncTableEntry->pFunc;
};

static uint32_t ScriptInterpreter::GetCOMMFuncNumArgs(uint16_t funcId)
{
	uint16_t funcIdx = funcId & 0xFFF;
	uint8_t funcTableIdx = (funcId >> 12) & 0xF;
	ScriptCOMMFuncTableEntry_t* pFuncTableEntry = nullptr;

	if (funcTableIdx < 6)
	{
		uint32_t r4 = (funcId >> 9) & 0x78;
		if (funcIdx >= ScriptInterpreter::spScriptCOMMFuncTables[r4].numEntries)
			return pFuncTableEntry->numArgs;

		pFuncTableEntry = ScriptInterpreter::spScriptCOMMFuncTables[r4].pTable[funcIdx];
	}

	return pFuncTableEntry->numArgs;
};

static uint32_t ScriptInterpreter::ExecuteInstruction_PUSHI(ScriptInterpreter* instance)
{
	instance->mInstructionIndex++;

	uint32_t operand = instance->mpInstructions[instance->mInstructionIndex].operand32;

	if ((instance->mpScript->endianness & 1) != 0)
	{
		uint32_t r6 = (operand >> 8) & 0xff00;
		r6 = operand >> 24;
		r6 = (r6 & ~0xff0000) | ((operand << 8) & 0xff0000);
		r6 = operand << 24;
		operand = r6;
	}

	instance->mStackValueTypes[instance->mNumStackValues] = 0;
	instance->mStackValues[instance->mNumStackValues] = operand;

	return 1;
};

static uint32_t ScriptInterpreter::ExecuteInstruction_PUSHF(ScriptInterpreter* instance)
{
	instance->mInstructionIndex++;

	float operandf = instance->mpInstructions[instance->mInstructionIndex].operandf;

	if ((instance->mpScript->endianness & 1) != 0)
	{
		uint32_t operand32 = instance->mpInstructions[instance->mInstructionIndex].operand32;

		uint32_t r6 = (operand32 >> 8) & 0xff00;
		r6 = operand32 >> 24;
		r6 = (r6 & ~0xff0000) | ((operand32 << 8) & 0xff0000);
		r6 = operand32 << 24;
		operandf = *(float*)&r6;
	}

	instance->mStackValueTypes[instance->mNumStackValues] = 1;
	instance->mStackValues[instance->mNumStackValues] = operandf;

	return 1;
};

static uint32_t ScriptInterpreter::ExecuteInstruction_PUSHIX(ScriptInterpreter* instance)
{
	uint16_t operand16 = instance->mpInstructions[instance->mInstructionIndex].operand16;

	if ((instance->mpScript->endianness & 1) != 0)
	{
		uint32_t r6 = (operand16 << 8) & 0xFFFF00;
		r6 = (r6 & ~0xFF) | ((operand16 << 8) & 0xFF);
		operand16 = r6;
	}

	instance->mStackValueTypes[instance->mNumStackValues++] = 0;
	instance->mStackValues[instance->mNumStackValues++] = ScriptInterpreter::spStaticIntVariablePool[operand16];

	return 1;
};

static uint32_t ScriptInterpreter::ExecuteInstruction_PUSHLIX(ScriptInterpreter* instance)
{
	uint16_t operand16 = instance->mpInstructions[instance->mInstructionIndex].operand16;

	if ((instance->mpScript->endianness & 1) != 0)
	{
		uint32_t r6 = (operand16 << 8) & 0xFFFF00;
		r6 = (r6 & ~0xFF) | ((operand16 << 8) & 0xFF);
		operand16 = r6;
	}

	instance->mStackValueTypes[instance->mNumStackValues++] = 0;
	instance->mStackValues[instance->mNumStackValues++] = instance->mpLocalIntVariablePool[operand16];

	return 1;
}

static uint32_t ScriptInterpreter::ExecuteInstruction_COMM(ScriptInterpreter* instance)
{
	uint32_t instructionIndex = instance->mInstructionIndex;
	uint16_t operand = instance->mpInstructions[instructionIndex].operand16;

	if ((instance->mpScript->endianness & 1) != 0)
	{
		uint32_t r3 = (operand << 8) & ~0xFF;
		operand = (r3 & ~0xff) | ((operand >> 8) & 0xff);
	}

	instance->mREGValueType = 6;
	spInstance = instance;
	uint32_t result = instance->GetCOMMFuncPtr(operand)->pFunc();

	if (result)
	{
		instance->mNumStackValues -= instance->GetCOMMFuncNumArgs(operand);

		if (instance->mInstructionIndex == instructionIndex)
		{
			instance->mInstructionIndex++;
		}

		result = 1;
	}
	else
	{
		result = 2;
	}

	return result;
};

static uint32_t ScriptInterpreter::ExecuteInstruction_END(ScriptInterpreter* instance)
{
	if (instance->mNumStackValues != 0)
	{
		instance->mInstructionIndex = instance->PopIntValue() + 1;
		return 1;
	}
	else
	{
		return 0;
	}
};

static uint32_t ScriptInterpreter::ExecuteInstruction_JUMP(ScriptInterpreter* instance)
{
	uint16_t operand = instance->mpInstructions[instance->mInstructionIndex]->operand16;

	if (!instance->mpHeader->endianness & 1)
	{
		r6 = (operand << 8) & 0xFFFF00;
		r6 = (r6 & ~0xFF) | ((operand >> 8) & 0xFF);
		operand = r6;
	}

	instance->mInstructionIndex = instance->mpProcedureLabels[operand].instructionIndex;

	return 1;
};

static uint32_t ScriptInterpreter::ExecuteInstruction_CALL(ScriptInterpreter* instance)
{
	instance->mStackValueTypes[instance->mNumStackValues] = 4;
	instance->mStackValues[instance->mNumStackValues] = instance->mInstructionIndex;
	instance->mNumStackValues++;

	uint16_t operand16 = instance->mpInstructions[instance->mInstructionIndex].operand16;
	if (instance->mpHeader->endianness & 1 != 0)
	{
		uint32_t r6 = (operand16 << 8) & 0xFFFF00;
		r6 = (r6 & ~0xFF) | ((operand16 >> 8) & 0xFF);
		operand16 = r6;
	}

	instance->mInstructionIndex = instance->mpProcedureLabels[operand16].instructionIndex;

	return 1;
};

static uint32_t ScriptInterpreter::ExecuteInstruction_GOTO(ScriptInterpreter* instance)
{
	uint16_t operand = instance->mpInstructions[instance->mInstructionIndex]->operand16;

	if (!instance->mpHeader->endianness & 1)
	{
		r6 = (operand << 8) & 0xFFFF00;
		r6 = (r6 & ~0xFF) | ((operand >> 8) & 0xFF);
		operand = r6;
	}

	instance->mInstructionIndex = instance->mpJumpLabels[operand].instructionIndex;

	return 1;
};

static uint32_t ScriptInterpreter::ExecuteInstruction_IF(ScriptInterpreter* instance)
{
	uint8_t type = instance->mStackValueTypes[instance->mNumStackValues];

	if (type != 4)
	{
		if (type == 3 || type == 1)
		{
			f1 = instance->PopFloatValue();

			if (f1 == 0.0f)
			{
				r3 = 0;
			}
			else
			{
				r3 = 1;
			}
		}
		else if (type == 2 || type == 0)
		{
			r3 = instance->PopIntValue();
		}

		if (r3 == 0)
		{
			instance->mInstructionIndex++;
			return 1;
		}
	}
	
	uint16_t operand = instance->mpInstructions[instance->mInstructionIndex].operand16;

	if (!instance->mpHeader->endianness & 1)
	{
		uint32_t r3 = (operand << 8) & 0xFFFF00;
		r3 = (r3 & 0xFFFFFF00) | ((operand >> 8) & 0xFF);
		operand = r3;
	}

	instance->mInstructionIndex = instance->mpJumpLabels[operand].instructionIndex;
	return 1;
};