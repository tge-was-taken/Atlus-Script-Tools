
// types
#include <stdint.h>

// memcpy
#include <cstring>

class MessageScriptInterpreter;

typedef int (*MessageScriptInterpreterFunction)(uint32_t functionId, MessageScriptInterpreter* pInterpreter);

typedef struct
{
	/* 0x00 */ MessageScriptInterpreterFunction* pFuncs;
	/* 0x04 */ uint32_t numEntries;

} MessageScriptInterpreterFunctionTable_t;

class MessageScriptInterpreter
{
	// Const fields
	const MessageScriptInterpreterFunctionTable_t cpFunctionTables[7];

	const uint32_t cTextColorCount = 30;
	const uint32_t cTextColorTableSize = cTextColorCount * sizeof(uint32_t);
	const uint32_t cpTextColorTable[cTextColorCount] =
	{
		0xFFFFFFFF, // 0: white
		0x72C5FFFF, // 1: light blue
		0xFF423FFF, // 2: light red
		0xFFFF76FF, // 3: light yellow
		0x69FF65FF, // 4: light green
		0x50321EFF, // 5: dark brown
		0xDC6E00FF, // 6: dark orange
		0xFFFFFFFF, // 7: white
		0x50321EFF, // 8: dark brown
		0xFF1800FF, // 9: red
		0xBA0000FF, // 10: dark red
		0x1200FFFF, // 11: blue
		0x1F00BAFF, // 12: dark blue
		0x0AC000FF, // 13: green
		0x078600FF, // 14: dark green
		0x9D00EFFF, // 15: purple
		0x78008EFF, // 16: dark purple
		0xBF9D02FF, // 17: dark yellow
		0xFF0391FF, // 18: pink
		0xFF00FCFF, // 19: dark pink
		0xBD0054FF, // 20: darker pink
		0x00AEFFFF, // 21: light teal
		0x90401AFF, // 22: dark brown
		0x161616FF, // 23: light black
		0x404040FF, // 24: dark gray
		0x656565FF, // 25: gray
		0xE6B625FF, // 26: dark yellow
		0xFFFFFFFF, // 27: white
		0x99BBD3FF, // 28: dark teal
		0xE4D4C7FF, // 29: really light brown
	};

	// Static fields
	static uint32_t sDword1;
	static uint32_t sDword2;

	// Static functions
	static uint32_t ExecuteFunction(uint8_t functionSignifier, MessageScriptInterpreter* pInterpreter);

	// 0 1
	static uint32_t SetTextColor(uint32_t functionid, MessageScriptInterpreter* pInterpreter);
	
	// 0 5
	static uint32_t FunctionTable0_Function5(uint32_t functionId, MessageScriptInterpreter* pInterpreter);
	
	// 2 1
	static uint32_t FunctionTable2_Function1(uint32_t functionId, MessageScriptInterpreter* pInterpreter);
	
	// 4 6
	static uint32_t SetBustup(uint32_t functionid, MessageScriptInterpreter* pInterpreter);
	
	// 4 10
	static uint32_t FunctionTable4_Function10(uint32_t functionid, MessageScriptInterpreter* pInterpreter);

	// Instance fields
	/* 0x000d */ uint8_t field0d; // referenced by SetTextColor
	/* 0x000f */ uint8_t field0f; // referenced by FunctionTable2_Function1
	/* 0x0018 */ uint8_t* mpMessageData;
	/* 0x0020 */ uint32_t mMessageDataIndex;
	/* 0x0028 */ uint8_t field28;
	/* 0x002a */ uint16_t field2a;
	/* 0x002c */ uint32_t mTextColor;
	/* 0x003c */ void(*field3c)(uint32_t, uint32_t, uint32_t);
	/* 0x0040 */ uint32_t field40;

	// Instance functions
	uint16_t GetArgumentValue(uint32_t index);
};

int16_t MessageScriptInterpreter::GetArgumentValue(uint32_t index)
{
	uint8_t secondByte = 0;
	uint8_t secondByteAux = this->mpMessageData[this->mMessageDataIndex + (index * 2) + 1]; // byte

	if (secondByteAux != 0xFF)
	{
		secondByte = (secondByteAux - 1) & 0xFF;
	}

	uint8_t firstByte = this->mpMessageData[this->mMessageDataIndex + (index * 2)] - 1;

	return (int16_t)((firstByte & ~0xFF00) | ((secondByte << 8) & 0xFF00));
}

static MessageScriptInterpreter::ExecuteFunction(uint8_t functionSignifier, MessageScriptInterpreter* pInterpreter)
{
	uint32_t functionId = (functionSignifier << 8) | pInterpreter->mpMessageData[pInterpreter->mMessageDataIndex++];

	if (pInterpreter->field3c != nullptr)
	{
		pInterpreter->field3c(pInterpreter, functionId, pInterpreter->field40);
	}

	uint32_t functionTableIndex = (functionId & 0xE0) >> 5; // extract high 3 bits
	uint32_t functionIndex = functionId & 0x1F; // extract low 5 bits
	uint32_t result = MessageScriptInterpreter::cpFunctionTables[functionTableIndex].pFuncs[functionIndex](functionId, pInterpreter);
	
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

// 0 1
static uint32_t MessageScriptInterpreter::SetTextColor(uint32_t functionId, MessageScriptInterpreter* pInterpreter)
{
	int16_t colorIndex = pInterpreter->GetArgumentValue(0);

	if (MessageScriptInterpreter::sDword1 != 5 && MessageScriptInterpreter::sDword1 != 0)
		return 0;

	if (colorIndex < 0 && colorIndex >= MessageScriptInterpreter::cTextColorCount)
		return 0;

	uint32_t textColorTableCopy[MessageScriptInterpreter::cTextColorTableSize];
	memcpy(textColorTableCopy, MessageScriptInterpreter::cpTextColorTable, MessageScriptInterpreter::cTextColorTableSize);
	
	pInterpreter->field0d = 0;
	pInterpreter->mTextColor = textColorTableCopy[colorIndex];

	return 0;
};

// 0 5
static uint32_t MessageScriptInterpreter::FunctionTable0_Function5(uint32_t functionId, MessageScriptInterpreter* pInterpreter)
{
	// it literally does nothing
	return 0;
};

// 2 1
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

// 2 7
static uint32_t MessageScriptInterpreter::FunctionTable2_Function7(uint32_t functionId, MessageScriptInterpreter* pInterpreter)
{
	// 0x570B0C
	// calls GameState::SetBit
};

//  4 6 (F6 86)
static uint32_t MessageScriptInterpreter::SetBustup(uint32_t functionId, MessageScriptInterpreter* pInterpreter)
{
	if (MessageScriptInterpreter::sDword1 == 0)
	{
		ImageManager::DisplayBustup(pInterpreter->GetArgumentValue(1), pInterpreter->GetArgumentValue(2), pInterpreter->GetArgumentValue(3), pInterpreter->GetArgumentValue(4), pInterpreter->GetArgumentValue(0));
		ImageManager::IncrementUnk();
	}

	return 0;
};

// 4 10 (F4 8A)
static uint32_t MessageScriptInterpreter::FunctionTable4_Function10(uint32_t functionId, MessageScriptInterpreter* pInterpreter)
{
	// 0x571F68
	// complex function so wip
};
