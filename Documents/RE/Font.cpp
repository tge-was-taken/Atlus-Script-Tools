
// types
#include <stdint.h>

typedef struct 
{
	/* 0x00 */ uint32_t headerSize;
	/* 0x04 */ uint32_t field04; // 0xF4A86, 0xA3C3
	/* 0x08 */ uint8_t field08;
	/* 0x09 */ uint8_t field09;
	/* 0x0a */ uint8_t numPalettes;
	/* 0x0b */ uint8_t field0b;
	/* 0x0c */ uint16_t field0c;
	/* 0x0e */ uint16_t numGlyphs;
	/* 0x10 */ uint16_t glyphHeight;
	/* 0x12 */ uint16_t glyphWidth;
	/* 0x14 */ uint16_t paletteSize;
	/* 0x16 */ uint8_t hasSection2And3;
	/* 0x17 */ uint8_t field17[9];

} FontHeader_t;

typedef struct
{
	uint32_t sectionSize;

} FontSectionHeader_t;

typedef struct
{
	/* 0x00 */ uint32_t headerSize;				// 0x20
	/* 0x04 */ uint32_t dictionarySize;			// 0xD8
	/* 0x08 */ uint32_t compressedSize;			// 0xE3378
	/* 0x0C */ uint32_t uncompressedSize;		// 0x719BB4
	/* 0x10 */ uint32_t field10;				// 0x400, equal to second glyph offset
	/* 0x14 */ uint32_t numGlyphs;				// 0xEB7
	/* 0x18 */ uint32_t glyphOffsetTableSize;	// 0x3ADC
	/* 0x1C */ uint32_t field1C;				// 0x3AD800

} FontCompressionHeader_t;

class FontManager
{

};

static void FontManager::SwapField(uint8_t* pData, uint32_t typeSize)
{
	if (typeSize == 4)
	{
		uint8_t byte1 = *(pData + 0);
		uint8_t byte2 = *(pData + 1);
		uint8_t byte3 = *(pData + 2);
		uint8_t byte4 = *(pData + 3);
		*(pData + 1) = uint8_t byte3;
		*(pData + 0) = uint8_t byte4;
		*(pData + 2) = uint8_t byte2;
		*(pData + 3) = uint8_t byte1;
	}
	else if (typeSize == 2)
	{
		uint8_t byte1 = *(pData + 0);
		uint8_t byte2 = *(pData + 1);
		*(pData + 1) = uint8_t byte1;
		*(pData + 0) = uint8_t byte2;
	}
};

static void FontManager::SwapHeaders(void* pData)
{
	FontHeader_t* pHeader = (FontHeader_t*)pData;

	FontManager::SwapField(&pHeader->headerSize,		sizeof(uint32_t));
	FontManager::SwapField(&pHeader->field04,			sizeof(uint32_t));
	FontManager::SwapField(&pHeader->field08,			sizeof(uint8_t));
	FontManager::SwapField(&pHeader->field09,			sizeof(uint8_t));
	FontManager::SwapField(&pHeader->numPalettes,		sizeof(uint8_t));
	FontManager::SwapField(&pHeader->field0b,			sizeof(uint8_t));
	FontManager::SwapField(&pHeader->field0c,			sizeof(uint16_t));
	FontManager::SwapField(&pHeader->numGlyphs,			sizeof(uint16_t));
	FontManager::SwapField(&pHeader->glyphHeight,		sizeof(uint16_t));
	FontManager::SwapField(&pHeader->glyphWidth,		sizeof(uint16_t));
	FontManager::SwapField(&pHeader->paletteSize,		sizeof(uint16_t));
	FontManager::SwapField(&pHeader->hasSection2And3,	sizeof(uint8_t));

	for (int i = 0; i < 9; i++)
	{
		FontManager::SwapField(&pHeader->field17[i], sizeof(uint8_t));
	}

	FontSectionHeader_t* pSectionHeader = pHeader;

	if (pHeader->hasSection2And3 != 0)
	{
		pSectionHeader += (pHeader->headerSize + (pHeader->numPalettes * 1024));

		FontManager::SwapField(&pSectionHeader->sectionSize, sizeof(uint32_t));
		pSectionHeader += (pSectionHeader->sectionSize + sizeof(uint32_t));

		FontManager::SwapField(&pSectionHeader, sizeof(uint32_t));
		pSectionHeader += (pSectionHeader->sectionSize + sizeof(uint32_t));
	}

	FontCompressionHeader_t* pCompressionHeader = pSectionHeader + (pHeader->numGlyphs * sizeof(uint32_t));

	FontManager::SwapField(&pCompressionHeader->headerSize,				sizeof(uint32_t));
	FontManager::SwapField(&pCompressionHeader->dictionarySize,			sizeof(uint32_t));
	FontManager::SwapField(&pCompressionHeader->compressedSize,			sizeof(uint32_t));
	FontManager::SwapField(&pCompressionHeader->uncompressedSize,		sizeof(uint32_t));
	FontManager::SwapField(&pCompressionHeader->field10,				sizeof(uint32_t));
	FontManager::SwapField(&pCompressionHeader->numGlyphs,				sizeof(uint32_t));
	FontManager::SwapField(&pCompressionHeader->glyphOffsetTableSize,	sizeof(uint32_t));
	FontManager::SwapField(&pCompressionHeader->field1C,				sizeof(uint32_t));
};

static void FontManager::sub_573FA0(int arg1, FontHeader_t* arg2, void* pData)
{
	uint8_t arg1AsByte = (uint8_t)arg1;

	if (arg1AsByte != 0x15 && arg1AsByte != 0xE)
	{
		if (arg1AsByte != 0xF)
		{
			if (arg1AsByte != 0x10)
			{
				if (arg1AsByte != 0x11)
				{
					if (arg1AsByte != 0x12)
					{
						if (arg1AsByte != 0x13)
						{
							if (arg1AsByte != 0x13)
							{
								if (arg2 == 0)
								{
									if (pData != 0)
									{
										arg2 = pData;
									}
								}

								r3 = (arg1 * 20) & 0x1FE0;
								r7 = task_fontMan_dword1;
								r8 = r7 + r3;
								r8->field00 = r3;
								r8->field04 = arg2;
								r3 = arg2->field0a;
								r5 = arg2->field16;
								r3 = r3 << 10;
								eq = r5 == 0;
								r6 = arg2->headerSize + r3;

								if (!eq)
								{
									r5 = 0;
									r3 = r5;
									r8->field08 = r5;
									r8->field10 = r5;
								}
								else
								{
									r3 = arg2 + r6;
									r5 = arg2 + r6;
									r11 = r5 + 4;
									r3 = r3->field00;
									r10 = r3 + 4;
									r8->field08 = r3;
									r5 = r5 + r3;
									r10 = r6 + r10;
									r8->field10 = r11;
									r6 = r6 + r3;
									r10 = arg2 + r10;
									r5 = r5 + 8;
									r3 = r10->field00;
									r6 = r6 + r3;
									r6 = r6 + 8;
								}

								r11 = arg2->field0e;
								r10 = arg2 + r6;
								r8->field0c = r3;
								eq = arg1AsByte == 6;
								r11 = r11 << 2;
								r8->field14 = r5;
								r3 = r6 + r11;
								r8->field18 = r10;
								r3 = arg2 + r3;
								r8->field1c = r3;

								if (eq)
								{
									r3 = r7->fieldc0;
									r4 = r7->fieldc4;
									r5 = r7->fieldc8;
									r6 = r7->fieldcc;
									r7->field1c0 = r3;
									r7->field1c4 = r4;
									r8 = r7->fieldd0;
									r7->field1c8 = r5;
									r9 = r7->fieldd4;
									r7->field1cc = r6;
									r10 = r7->fieldd8;
									r11 = f7->fielddc;
									r7->field1d0 = r8;
									r7->field1d4 = r9;
									r7->field1d8 = r10;
									r7->field1dc = r11;
									r7->field1e0 = r3;
									r7->field1e4 = r4;
									r7->field1e8 = r5;
									r7->field1ec = r6;
									r7->field1f0 = r8;
									r7->field1f4 = r9;
									r7->field1f8 = r10;
									r7->field1fc = r11;
									r7->field200 = r3;
									r7->field204 = r4;
									r7->field208 = r5;
									r7->field20C = r6;
									r7->field210 = r8;
									r7->field214 = r9;
									r7->field218 = r10;
									r7->field21C = r11;
								}
								else
								{
									if (r9 == 7)
									{
										r3 = r7->fielde0;
										r4 = r7->fielde4;
										r5 = r7->fielde8;
										r6 = r7->fieldec;
										r7->field220 = r3;
										r7->field224 = r4;
										r8 = r7->fieldf0;
										r7->field228 = r5;
										r9 = r7->fieldf4;
										r7->field22c = r6;
										r10 = r7->fieldf8;
										r11 = r7->fieldfc;
										r7->field230 = r8;
										r7->field234 = r9;
										r7->field238 = r10;
										r7->field23c = r11;
										r7->field240 = r3;
										r7->field244 = r4;
										r7->field248 = r5;
										r7->field24c = r6;
										r7->field250 = r8;
										r7->field254 = r9;
										r7->field258 = r10;
										r7->field25c = r11;
										r7->field260 = r3;
										r7->field264 = r4;
										r7->field26c = r6;
										r7->field270 = r8;
										r7->field274 = r9;
										r7->field278 = r10;
										r7->field27c = r11;
									}
								}
							}
						}
					}
				}
			}
		}
	}
};