using System.Runtime.InteropServices;

namespace AtlusScriptLib.MessageScript
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = SIZE)]
    public struct MessageScriptBinaryHeader
    {
        public const int SIZE = 32;
        public const int FILE_TYPE = 7;
        public static byte[] MAGIC_LE = new byte[] { (byte)'M', (byte)'S', (byte)'G', (byte)'1' };
        public static byte[] MAGIC_BE = new byte[] { (byte)'1', (byte)'G', (byte)'S', (byte)'M' };

        // 00
        public byte FileType;

        // 01
        [MarshalAs(UnmanagedType.U1)]
        public bool IsCompressed;

        // 02
        public short UserId;

        // 04
        public int FileSize;

        // 08
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Magic;

        // 0C
        public int Field0C;

        // 10
        public int RelocationTableOffset;

        // 14
        public int RelocationTableSize;

        // 18
        public int MessageCount;

        // 1C
        [MarshalAs(UnmanagedType.U2)]
        public bool IsRelocated;

        // 1E
        public short Field1E;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = SIZE)]
    public struct MessageScriptBinaryMessageHeader
    {
        public const int SIZE = 8;

        // 00
        public int Type;

        // 04
        public int Offset;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = SIZE)]
    public struct MessageScriptBinarySpeakerTableHeader
    {
        public const int SIZE = 10;

        // 00
        public int SpeakerNameTableOffset; // points to array of char*

        // 04
        public int SpeakerCount;

        // 08
        public int Field08;

        // 0C
        public int Field0C;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1, Size = SIZE)]
    public struct MessageScriptBinaryMessageDialogHeader
    {
        public const int SIZE = 28;

        // 0x00
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
        public string Identifier;

        // 0x18
        public short DialogCount;

        // 0x1A
        public short SpeakerId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1, Size = SIZE)]
    public struct MessageScriptBinaryMessageSelectionDialogHeader
    {
        public const int SIZE = 32;

        // 00
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
        public string Identifier;

        // 18
        public short Field18;

        // 1A
        public short OptionCount;

        // 1C
        public short Field1C;

        // 1E
        public short Field1E;
    }
}
