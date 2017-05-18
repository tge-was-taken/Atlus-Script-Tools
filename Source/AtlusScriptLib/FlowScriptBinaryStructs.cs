using System;
using System.Runtime.InteropServices;

namespace AtlusScriptLib
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = SIZE)]
    public struct FlowScriptBinaryHeader
    {
        public const int SIZE = 32;
        public const int FILE_TYPE = 0;
        public static byte[] MAGIC = new byte[] { (byte)'F', (byte)'L', (byte)'W', (byte)'0' };

        // 0x00
        public byte FileType;

        // 0x01
        [MarshalAs(UnmanagedType.I1)]
        public bool Compressed;

        // 0x02
        public short UserId;

        // 0x04
        public int FileSize;

        // 0x08
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Magic;

        // 0x0C
        public int Field0C;

        // 0x10
        public int SectionCount;

        // 0x14
        public short LocalIntVariableCount;

        // 0x16
        public short LocalFloatVariableCount;

        // 0x18
        public short Endianness;

        // 0x1A
        public short Field1A;

        // 0x1C
        public int Padding;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = SIZE)]
    public struct FlowScriptBinarySectionHeader
    {
        public const int SIZE = 16;

        // 0x00
        [MarshalAs(UnmanagedType.U4)]
        public FlowScriptBinarySectionType SectionType;

        // 0x04
        public int ElementSize;

        // 0x08
        public int ElementCount;

        // 0x0C
        public int FirstElementAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FlowScriptBinaryLabel
    {
        public const int SIZE_V1 = 32;
        public const int SIZE_V2 = 56;
        public const int SIZE_V3 = 48;

        public string Name;
        public int InstructionIndex;
        public int Reserved;
    }

    // unuon
    public struct FlowScriptBinaryInstruction
    {
        public const int SIZE = 4;

    // union 
    // {
        public FlowScriptOpcode Opcode;
        public short OperandShort;
    // }

    // union 
    // {
        public int OperandInt;
        public float OperandFloat;
    // }
    }
}
