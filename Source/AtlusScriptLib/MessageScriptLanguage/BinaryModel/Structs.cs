using System.Collections.Generic;
using AtlusScriptLib.Common.IO;

namespace AtlusScriptLib.MessageScriptLanguage.BinaryModel
{
    public struct BinaryHeader
    {
        public const int SIZE = 32;

        public const byte FILE_TYPE = 7;

        // ReSharper disable once InconsistentNaming
        public static byte[] MAGIC_V0 { get; } = { ( byte )'M', ( byte )'S', ( byte )'G', ( byte )'0' };

        // ReSharper disable once InconsistentNaming
        public static byte[] MAGIC_V1 { get; } = { ( byte )'M', ( byte )'S', ( byte )'G', ( byte )'1' };

        // ReSharper disable once InconsistentNaming
        public static byte[] MAGIC_V1_BE { get; } = { ( byte ) '1', ( byte ) 'G', ( byte ) 'S', ( byte ) 'M' };

        // 00
        public byte FileType;

        // 01
        public bool IsCompressed;

        // 02
        public short UserId;

        // 04
        public int FileSize;

        // 08
        public byte[] Magic;

        // 0C
        public int Field0C;

        // 10
        public OffsetTo<byte[]> RelocationTable;

        // 14
        public int RelocationTableSize;

        // 18
        public int WindowCount;

        // 1C
        public bool IsRelocated;

        // 1E
        public short Field1E;
    }

    public struct BinaryWindowHeader
    {
        public const int SIZE = 8;

        // 00
        public BinaryWindowType WindowType;

        // 04
        public OffsetTo<object> Window;
    }

    public struct BinarySpeakerTableHeader
    {
        public const int SIZE = 10;

        // 00
        public OffsetTo<OffsetTo<List<byte>>[]> SpeakerNameArray;

        // 04
        public int SpeakerCount;

        // 08
        public int Field08;

        // 0C
        public int Field0C;
    }

    // Variable length
    public struct BinaryDialogueWindow
    {
        public const int IDENTIFIER_LENGTH = 24;

        // 0x00 
        public string Identifier;

        // 0x18
        public short LineCount;

        // 0x1A
        public ushort SpeakerId;

        // 0x1C
        public int[] LineStartAddresses;

        // 0x1C + LineCount * 4
        public int TextBufferSize;

        // 0x1C + LineCount * 4 + 4
        public byte[] TextBuffer;
    }

    // Variable length
    public struct BinarySelectionWindow
    {
        public const int IDENTIFIER_LENGTH = 24;

        // 0x00
        public string Identifier;

        // 0x18
        public short Field18;

        // 0x1A
        public short OptionCount;

        // 0x1C
        public short Field1C;

        // 0x1E
        public short Field1E;

        // 0x20
        public int[] OptionStartAddresses;

        // 0x20 + OptionCount * 4
        public int TextBufferSize;

        // 0x20 + OptionCount * 4 + 4
        public byte[] TextBuffer;
    }
}
