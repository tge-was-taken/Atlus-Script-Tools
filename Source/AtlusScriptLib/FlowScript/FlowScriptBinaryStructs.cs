using System.Runtime.InteropServices;

namespace AtlusScriptLib.FlowScript
{
    [StructLayout(LayoutKind.Sequential)]
    public struct FlowScriptBinaryHeader
    {
        public const int SIZE = 32;
        public static byte[] MAGIC = new byte[] { (byte)'F', (byte)'L', (byte)'W', (byte)'0' };

        public byte FileType;
        public byte Compressed;
        public short UserId;
        public int FileSize;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Magic;

        public int Reserved1;
        public int SectionCount;
        public short Field14;
        public short Field16;
        public short Reserved2;
        public short Reserved3;
        public short Reserved4;
        public short Reserved5;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FlowScriptBinarySectionHeader
    {
        public const int SIZE = 16;

        public FlowScriptBinarySectionType sectionType;
        public int UnitSize;
        public int UnitCount;
        public int StartOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FlowScriptBinaryLabel
    {
        public const int SIZE_V1 = 32;
        public const int SIZE_V2 = 56;
        public const int SIZE_V3 = 48;

        public string Name;
        public int Offset;
        public int Reserved;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct FlowScriptBinaryInstructionInternal
    {
        public const int SIZE = 4;

        [FieldOffset(0)]
        public FlowScriptBinaryOpcode Opcode;

        [FieldOffset(2)]
        public short OperandShort;

        [FieldOffset(0)]
        public int OperandInt;

        [FieldOffset(0)]
        public float OperandFloat;
    }

    // required for fixups
    public struct FlowScriptBinaryInstruction
    {
        public FlowScriptBinaryOpcode Opcode;
        public short OperandShort;
        public int OperandInt;
        public float OperandFloat;
    }
}
