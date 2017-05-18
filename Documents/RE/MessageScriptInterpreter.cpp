
// types
#include <stdint.h>

class MessageScriptInterpreter;

typedef int (*MessageScriptInterpreterFunction)(uint32_t functionId, MessageScriptInterpreter* pInterpreter);

typedef struct
{
	/* 0x00 */ MessageScriptInterpreterFunction* pFuncs;
	/* 0x04 */ uint32_t numEntries;

} MessageScriptInterpreterFunctionTable_t;

class MessageScriptInterpreter
{
	// Static fields
	static MessageScriptInterpreterFunctionTable_t spFunctionTables[7];
	static uint32_t sDword1;
	static uint32_t sDword2;

	// Static functions
	static uint32_t ExecuteFunction(uint8_t functionSignifier, MessageScriptInterpreter* pInterpreter);

	static uint32_t FunctionTable0_Function5(uint32_t functionId, MessageScriptInterpreter* pInterpreter);
	static uint32_t FunctionTable2_Function1(uint32_t functionId, MessageScriptInterpreter* pInterpreter);
	static uint32_t Function_DisplayBustup(uint32_t functionid, MessageScriptInterpreter* pInterpreter);
	static uint32_t FunctionTable4_Function10(uint32_t functionid, MessageScriptInterpreter* pInterpreter);
	

	// Instance fields
	/* 0x000F */ uint8_t field0f;
	/* 0x0018 */ uint8_t* mpMessageData;
	/* 0x0020 */ uint32_t mMessageDataIndex;
	/* 0x0028 */ uint8_t field28;
	/* 0x002a */ uint16_t field2a;
	/* 0x003c */ void(*field3c)(uint32_t, uint32_t, uint32_t);
	/* 0x0040 */ uint32_t field40;

	// Instance functions
	uint16_t GetArgumentValue(uint32_t index);
};

static MessageScriptInterpreter::ExecuteFunction(uint8_t functionSignifier, MessageScriptInterpreter* pInterpreter)
{
	uint32_t functionId = (functionSignifier << 8) | pInterpreter->mpMessageData[pInterpreter->mMessageDataIndex++];

	if (pInterpreter->field3c != nullptr)
	{
		pInterpreter->field3c(pInterpreter, functionId, pInterpreter->field40);
	}

	uint32_t functionTableIndex = (functionId & 0xE0) >> 5; // extract high 3 bits
	uint32_t functionIndex = functionId & 0x1F; // extract low 5 bits
	uint32_t result = MessageScriptInterpreter::spFunctionTables[functionTableIndex].pFuncs[functionIndex](functionId, pInterpreter);
	
	uint32_t numArgs = (((functionId >> 8) & 0xF) - 1) * 2;
	pInterpreter->mMessageDataIndex += numArgs;

	if (result != 0)
	{
		return 1;
	}

	if (pInterpreter->field28 == 0)
	{
		pInterpreter->field28 = 1;
	}

	return 0;
};

uint16_t MessageScriptInterpreter::GetArgumentValue(uint32_t index)
{
	uint8_t secondByte = 0;
	uint8_t secondByteAux = this->mpMessageData[this->mMessageDataIndex + (index * 2) + 1]; // byte

	if (secondByteAux != 0xFF)
	{
		secondByte = (secondByteAux - 1) & 0xFF;
	}

	uint8_t firstByte = this->mpMessageData[this->mMessageDataIndex + (index * 2)] - 1;

	return (firstByte & ~0xFF00) | ((secondByte << 8) & 0xFF00);
}

// [f 0 5 ffff]
static uint32_t MessageScriptInterpreter::FunctionTable0_Function5(uint32_t functionId, MessageScriptInterpreter* pInterpreter)
{
	return 0;
};

// [f 2 1]
static uint32_t MessageScriptInterpreter::FunctionTable2_Function1(uint32_t functionId, MessageScriptInterpreter* pInterpreter)
{
	if (MessageScriptInterpreter::sDword1 == 0)
	{
		pInterpreter->field0f = 0x28;
		pInterpreter->field2a = 0x20;
		MessageScriptInterpreter::sDword2 = 0;
	}

	return 0;
};

// [f 2 7] (F5 47)
static uint32_t MessageScriptInterpreter::FunctionTable2_Function7(uint32_t functionId, MessageScriptInterpreter* pInterpreter)
{
	// 0x570B0C
	// calls GameState::SetBit
};

//  [f 4 6] (F6 86)
static uint32_t MessageScriptInterpreter::Function_DisplayBustup(uint32_t functionId, MessageScriptInterpreter* pInterpreter)
{
	if (MessageScriptInterpreter::sDword1 == 0)
	{
		Facility::DisplayBustup(pInterpreter->GetArgumentValue(1), pInterpreter->GetArgumentValue(2), pInterpreter->GetArgumentValue(3), pInterpreter->GetArgumentValue(4), pInterpreter->GetArgumentValue(0));
		Facility::IncrementUnk();
	}

	return 0;
};

// [f 4 10] (F4 8A)
static uint32_t MessageScriptInterpreter::FunctionTable4_Function10(uint32_t functionId, MessageScriptInterpreter* pInterpreter)
{
	// 0x571F68
	// complex function so wip
};
