using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;

namespace AtlusScriptLib.IO
{
    public class EndianBinaryReader : BinaryReader
    {
        private StringBuilder m_StringBuilder   = new StringBuilder();
        private Endianness m_Endianness;
        private bool m_Swap                     = false;

        public Endianness Endianness
        {
            get { return m_Endianness; }
            set
            {
                if (value != EndiannessHelper.SystemEndianness)
                    m_Swap = true;
                else
                    m_Swap = false;

                m_Endianness = value;
            }
        }

        public bool EndiannessNeedsSwapping
        {
            get { return m_Swap; }
        }

        public long Position
        {
            get { return BaseStream.Position; }
            set { BaseStream.Position = value; }
        }

        public long BaseStreamLength
        {
            get { return BaseStream.Length; }
        }

        public EndianBinaryReader(Stream input, Endianness endianness)
            : base(input)
        {
            Endianness = endianness;
        }

        public EndianBinaryReader(Stream input, Encoding encoding, Endianness endianness)
            : base(input, encoding)
        {
            Endianness = endianness;
        }

        public EndianBinaryReader(Stream input, Encoding encoding, bool leaveOpen, Endianness endianness)
            : base(input, encoding, leaveOpen)
        {
            Endianness = endianness;
        }

        public void Seek(long offset, SeekOrigin origin)
        {
            BaseStream.Seek(offset, origin);
        }

        public void SeekBegin(long offset)
        {
            BaseStream.Seek(offset, SeekOrigin.Begin);
        }

        public void SeekCurrent(long offset)
        {
            BaseStream.Seek(offset, SeekOrigin.Current);
        }

        public void SeekEnd(long offset)
        {
            BaseStream.Seek(offset, SeekOrigin.End);
        }

        public override decimal ReadDecimal()
        {
            if (m_Swap)
                return EndiannessHelper.SwapEndianness(base.ReadDecimal());
            else
                return base.ReadDecimal();
        }

        public decimal[] ReadDecimals(int count)
        {
            decimal[] array = new decimal[count];
            for (int i = 0; i < count; i++)
            {
                array[i] = ReadDecimal();
            }

            return array;
        }

        public override double ReadDouble()
        {
            if (m_Swap)
                return EndiannessHelper.SwapEndianness(base.ReadDouble());
            else
                return base.ReadDouble();
        }

        public double[] ReadDoubles(int count)
        {
            double[] array = new double[count];
            for (int i = 0; i < count; i++)
            {
                array[i] = ReadDouble();
            }

            return array;
        }

        public override short ReadInt16()
        {
            if (m_Swap)
                return EndiannessHelper.SwapEndianness(base.ReadInt16());
            else
                return base.ReadInt16();
        }

        public short[] ReadInt16s(int count)
        {
            short[] array = new short[count];
            for (int i = 0; i < count; i++)
            {
                array[i] = ReadInt16();
            }

            return array;
        }

        public override int ReadInt32()
        {
            if (m_Swap)
                return EndiannessHelper.SwapEndianness(base.ReadInt32());
            else
                return base.ReadInt32();
        }

        public int[] ReadInt32s(int count)
        {
            int[] array = new int[count];
            for (int i = 0; i < count; i++)
            {
                array[i] = ReadInt32();
            }

            return array;
        }

        public override long ReadInt64()
        {
            if (m_Swap)
                return EndiannessHelper.SwapEndianness(base.ReadInt64());
            else
                return base.ReadInt64();
        }

        public long[] ReadInt64s(int count)
        {
            long[] array = new long[count];
            for (int i = 0; i < count; i++)
            {
                array[i] = ReadInt64();
            }

            return array;
        }

        public override float ReadSingle()
        {
            if (m_Swap)
                return EndiannessHelper.SwapEndianness(base.ReadSingle());
            else
                return base.ReadSingle();
        }

        public float[] ReadSingles(int count)
        {
            float[] array = new float[count];
            for (int i = 0; i < count; i++)
            {
                array[i] = ReadInt64();
            }

            return array;
        }

        public override ushort ReadUInt16()
        {
            if (m_Swap)
                return EndiannessHelper.SwapEndianness(base.ReadUInt16());
            else
                return base.ReadUInt16();
        }

        public ushort[] ReadUInt16s(int count)
        {
            ushort[] array = new ushort[count];
            for (int i = 0; i < count; i++)
            {
                array[i] = ReadUInt16();
            }

            return array;
        }

        public override uint ReadUInt32()
        {
            if (m_Swap)
                return EndiannessHelper.SwapEndianness(base.ReadUInt32());
            else
                return base.ReadUInt32();
        }

        public uint[] ReadUInt32s(int count)
        {
            uint[] array = new uint[count];
            for (int i = 0; i < count; i++)
            {
                array[i] = ReadUInt32();
            }

            return array;
        }

        public override ulong ReadUInt64()
        {
            if (m_Swap)
                return EndiannessHelper.SwapEndianness(base.ReadUInt64());
            else
                return base.ReadUInt64();
        }

        public ulong[] ReadUInt64s(int count)
        {
            ulong[] array = new ulong[count];
            for (int i = 0; i < count; i++)
            {
                array[i] = ReadUInt64();
            }

            return array;
        }

        public string ReadCString()
        {
            m_StringBuilder.Clear();

            byte b;
            while ( (b = ReadByte()) != 0)
            {
                m_StringBuilder.Append((char)b);
            }

            return m_StringBuilder.ToString();
        }

        public string ReadCString(int fixedLength)
        {
            m_StringBuilder.Clear();

            byte b;
            for (int i = 0; i < fixedLength; i++)
            {
                b = ReadByte();

                if (b != 0)
                    m_StringBuilder.Append((char)b);
            }

            return m_StringBuilder.ToString();
        }

        public T ReadStruct<T>()
            where T : struct
        {
            T obj;

            var bytes = ReadBytes(Marshal.SizeOf<T>());

            unsafe
            {
                fixed (byte* ptr = bytes)
                {
                    obj = Marshal.PtrToStructure<T>((IntPtr)ptr);
                }
            }

            if (m_Swap)
                obj = EndiannessHelper.SwapEndianness(obj);

            return obj;
        }
    }
}
