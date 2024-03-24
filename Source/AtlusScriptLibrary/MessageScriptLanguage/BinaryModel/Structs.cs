using AtlusScriptLibrary.Common.IO;
using System.Collections.Generic;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

public struct BinaryHeader
{
    public const int SIZE = 32;

    public const byte FILE_TYPE = 7;

    // ReSharper disable once InconsistentNaming
    public static byte[] MAGIC_V0 { get; } = { (byte)'M', (byte)'S', (byte)'G', (byte)'0' };

    // ReSharper disable once InconsistentNaming
    public static byte[] MAGIC_V1 { get; } = { (byte)'M', (byte)'S', (byte)'G', (byte)'1' };

    // ReSharper disable once InconsistentNaming
    public static byte[] MAGIC_V1_BE { get; } = { (byte)'1', (byte)'G', (byte)'S', (byte)'M' };

    // 00
    public byte FileType;

    // 01
    public byte Format;

    // 02
    public short UserId;

    // 04
    public int FileSize;

    // 08
    public byte[] Magic;

    // 0C
    public int ExtSize;

    // 10
    public OffsetTo<byte[]> RelocationTable;

    // 14
    public int RelocationTableSize;

    // 18
    public int DialogCount;

    // 1C
    public bool IsRelocated;

    // 1D
    public byte Reserved;

    // 1E
    public short Version;
}

public struct BinaryDialogHeader
{
    public const int SIZE = 8;

    // 00
    public BinaryDialogKind Kind;

    // 04
    public OffsetTo<object> Data;
}

public struct BinarySpeakerTableHeader
{
    public const int SIZE = 10;

    // 00
    public OffsetTo<OffsetTo<List<byte>>[]> SpeakerNameArray;

    // 04
    public int SpeakerCount;

    // 08
    public int ExtDataOffset;

    // 0C
    public int Reserved;
}

// Variable length
public struct BinaryMessageDialog
{
    public const int IDENTIFIER_LENGTH = 24;

    // 0x00 
    public string Name;

    // 0x18
    public short PageCount;

    // 0x1A
    public ushort SpeakerId;

    // 0x1C
    public int[] PageStartAddresses;

    // 0x1C + LineCount * 4
    public int TextBufferSize;

    // 0x1C + LineCount * 4 + 4
    public byte[] TextBuffer;
}

// Variable length
public struct BinarySelectionDialog
{
    public const int IDENTIFIER_LENGTH = 24;

    // 0x00
    public string Name;

    // 0x18
    public short Ext;

    // 0x1A
    public short OptionCount;

    // 0x1C
    public BinarySelectionDialogPattern Pattern;

    // 0x1E
    public short Reserved;

    // 0x20
    public int[] OptionStartAddresses;

    // 0x20 + OptionCount * 4
    public int TextBufferSize;

    // 0x20 + OptionCount * 4 + 4
    public byte[] TextBuffer;
}
