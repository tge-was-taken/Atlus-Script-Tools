using AtlusScriptLibrary.Common.IO;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2;

public struct BinaryHeaderV2
{
    public const int SIZE = 0x18;
    public const uint VERSION = 0x10000;
    public static byte[] MAGIC { get; } = { (byte)0x78, (byte)0x56, (byte)0x34, (byte)0x12 };
    public static byte[] MAGIC_BE { get; } = { (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78 };

    // 0x00
    public byte[] Magic;

    // 0x04
    public uint Version;

    // 0x08
    public uint Field0C;

    // 0x0C
    public uint FileSize;

    // 0x10
    public OffsetTo<byte[]> RelocationTable;

    // 0x14
    public uint RelocationTableSize;
}

public struct BinaryHeader2
{
    public const int SIZE = 0x10;

    // 0x00
    public OffsetTo<OffsetTo<object>[]> DialogArray;

    // 0x04
    public uint DialogCount;

    // 0x08
    public uint DialogArrayEndOffset;

    // 0x0C
    public uint Field28;
}

public struct BinaryMessageDialogV2
{
    public const int IDENTIFIER_LENGTH = 32;

    // 0x00
    public BinaryDialogKind Type; // 0 = Message, 1 = Selection

    // 0x04
    public string Name;

    // 0x24
    public ushort PageCount;

    // 0x26
    public ushort SpeakerId;

    // 0x28
    public int[] PageStartAddresses;

    public byte[] TextBuffer;
}

public struct BinarySelectionDialogV2
{
    public const int IDENTIFIER_LENGTH = 32;

    // 0x00
    public BinaryDialogKind Type; // 0 = Message, 1 = Selection

    // 0x04
    public string Name;

    // 0x24
    public ushort OptionCount;

    // 0x26
    public ushort SpeakerId;

    // 0x28
    public int[] OptionStartAddresses;

    public uint TextBufferSize;

    public byte[] TextBuffer;
}