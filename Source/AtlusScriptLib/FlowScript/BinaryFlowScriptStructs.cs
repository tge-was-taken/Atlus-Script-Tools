using System.Runtime.InteropServices;

namespace AtlusScriptLib.FlowScript
{
    [StructLayout(LayoutKind.Sequential)]
    public struct BinaryFlowScriptHeader
    {
        public const int SIZE = 32;
        public static byte[] MAGIC = new byte[] { (byte)'F', (byte)'L', (byte)'W', (byte)'0' };

        public byte FileType;
        public byte Compressed;
        public ushort UserId;
        public uint FileSize;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Magic;

        public uint Reserved1;
        public uint SectionCount;
        public uint Field14;
        public ushort Reserved2;
        public ushort Reserved3;
        public ushort Reserved4;
        public ushort Reserved5;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BinaryFlowScriptSectionHeader
    {
        public const int SIZE = 16;

        public BinaryFlowScriptSectionType sectionType;
        public uint UnitSize;
        public uint UnitCount;
        public uint StartOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BinaryFlowScriptLabel
    {
        public const int SIZE_V1 = 32;
        public const int SIZE_V2 = 56;
        public const int SIZE_V3 = 48;

        public string Name;
        public uint Offset;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct BinaryFlowScriptInstructionInternal
    {
        public const int SIZE = 4;

        [FieldOffset(0)]
        public BinaryFlowScriptOpcode Opcode;

        [FieldOffset(2)]
        public short OperandShort;

        [FieldOffset(0)]
        public int OperandInt;

        [FieldOffset(0)]
        public float OperandFloat;
    }

    public struct BinaryFlowScriptInstruction
    {
        public BinaryFlowScriptOpcode Opcode;
        public short OperandShort;
        public int OperandInt;
        public float OperandFloat;
    }
}
