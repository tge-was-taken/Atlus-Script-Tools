using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace AtlusScriptLibrary.Common.IO
{
    public class EndianBinaryReader : BinaryReader
    {
        private StringBuilder mStringBuilder;
        private Endianness mEndianness;
        private bool mSwap;
        private Encoding mEncoding;
        private Queue<long> mPosQueue;

        public Endianness Endianness
        {
            get { return mEndianness; }
            set
            {
                if (value != EndiannessHelper.SystemEndianness)
                    mSwap = true;
                else
                    mSwap = false;

                mEndianness = value;
            }
        }

        public bool EndiannessNeedsSwapping
        {
            get { return mSwap; }
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
            Init(Encoding.Default, endianness);
        }

        public EndianBinaryReader(Stream input, Encoding encoding, Endianness endianness)
            : base(input, encoding)
        {
            Init(encoding, endianness);
        }

        public EndianBinaryReader(Stream input, Encoding encoding, bool leaveOpen, Endianness endianness)
            : base(input, encoding, leaveOpen)
        {
            Init(encoding, endianness);
        }

        private void Init(Encoding encoding, Endianness endianness)
        {
            mStringBuilder = new StringBuilder();
            mEncoding = encoding;
            mPosQueue = new Queue<long>();
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

        public void EnqueuePosition()
        {
            mPosQueue.Enqueue(Position);
        }

        public long PeekEnqueuedPosition()
        {
            return mPosQueue.Peek();
        }

        public void EnqueuePositionAndSeekBegin(long offset)
        {
            mPosQueue.Enqueue(Position);
            SeekBegin(offset);
        }

        public void SeekBeginToDequedPosition()
        {
            SeekBegin(mPosQueue.Dequeue());
        }

        public long DequeuePosition()
        {
            return mPosQueue.Dequeue();
        }

        public sbyte[] ReadSBytes(int count)
        {
            sbyte[] array = new sbyte[count];
            for (int i = 0; i < array.Length; i++)
                array[i] = ReadSByte();

            return array;
        }

        public bool[] ReadBooleans(int count)
        {
            bool[] array = new bool[count];
            for (int i = 0; i < array.Length; i++)
                array[i] = ReadBoolean();

            return array;
        }

        public override short ReadInt16()
        {
            if (mSwap)
                return EndiannessHelper.Swap(base.ReadInt16());
            return base.ReadInt16();
        }

        public short[] ReadInt16s(int count)
        {
            short[] array = new short[count];
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = ReadInt16();
            }

            return array;
        }

        public override ushort ReadUInt16()
        {
            if (mSwap)
                return EndiannessHelper.Swap(base.ReadUInt16());
            return base.ReadUInt16();
        }

        public ushort[] ReadUInt16s(int count)
        {
            ushort[] array = new ushort[count];
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = ReadUInt16();
            }

            return array;
        }

        public override decimal ReadDecimal()
        {
            if (mSwap)
                return EndiannessHelper.Swap(base.ReadDecimal());
            return base.ReadDecimal();
        }

        public decimal[] ReadDecimals(int count)
        {
            decimal[] array = new decimal[count];
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = ReadDecimal();
            }

            return array;
        }

        public override double ReadDouble()
        {
            if (mSwap)
                return EndiannessHelper.Swap(base.ReadDouble());
            return base.ReadDouble();
        }

        public double[] ReadDoubles(int count)
        {
            double[] array = new double[count];
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = ReadDouble();
            }

            return array;
        }

        public override int ReadInt32()
        {
            if (mSwap)
                return EndiannessHelper.Swap(base.ReadInt32());
            return base.ReadInt32();
        }

        public int[] ReadInt32s(int count)
        {
            int[] array = new int[count];
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = ReadInt32();
            }

            return array;
        }

        public override long ReadInt64()
        {
            if (mSwap)
                return EndiannessHelper.Swap(base.ReadInt64());
            return base.ReadInt64();
        }

        public long[] ReadInt64s(int count)
        {
            long[] array = new long[count];
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = ReadInt64();
            }

            return array;
        }

        public override float ReadSingle()
        {
            if (mSwap)
                return EndiannessHelper.Swap(base.ReadSingle());
            return base.ReadSingle();
        }

        public float[] ReadSingles(int count)
        {
            float[] array = new float[count];
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = ReadSingle();
            }

            return array;
        }

        public override uint ReadUInt32()
        {
            if (mSwap)
                return EndiannessHelper.Swap(base.ReadUInt32());
            return base.ReadUInt32();
        }

        public uint[] ReadUInt32s(int count)
        {
            uint[] array = new uint[count];
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = ReadUInt32();
            }

            return array;
        }

        public override ulong ReadUInt64()
        {
            if (mSwap)
                return EndiannessHelper.Swap(base.ReadUInt64());
            return base.ReadUInt64();
        }

        public ulong[] ReadUInt64s(int count)
        {
            ulong[] array = new ulong[count];
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = ReadUInt64();
            }

            return array;
        }

        public string ReadString(StringBinaryFormat format, int fixedLength = -1)
        {
            mStringBuilder.Clear();

            switch (format)
            {
                case StringBinaryFormat.NullTerminated:
                    {
                        byte b;
                        while ((b = ReadByte()) != 0)
                            mStringBuilder.Append((char)b);
                    }
                    break;

                case StringBinaryFormat.FixedLength:
                    {
                        if (fixedLength == -1)
                            throw new ArgumentException("Invalid fixed length specified");

                        byte b;
                        for (int i = 0; i < fixedLength; i++)
                        {
                            b = ReadByte();
                            if (b != 0)
                                mStringBuilder.Append((char)b);
                        }
                    }
                    break;

                case StringBinaryFormat.PrefixedLength8:
                    {
                        byte length = ReadByte();
                        for (int i = 0; i < length; i++)
                            mStringBuilder.Append((char)ReadByte());
                    }
                    break;

                case StringBinaryFormat.PrefixedLength16:
                    {
                        ushort length = ReadUInt16();
                        for (int i = 0; i < length; i++)
                            mStringBuilder.Append((char)ReadByte());
                    }
                    break;

                case StringBinaryFormat.PrefixedLength32:
                    {
                        uint length = ReadUInt32();
                        for (int i = 0; i < length; i++)
                            mStringBuilder.Append((char)ReadByte());
                    }
                    break;

                default:
                    throw new ArgumentException("Unknown string format", nameof(format));
            }

            return mStringBuilder.ToString();
        }

        public string[] ReadStrings(int count, StringBinaryFormat format, int fixedLength = -1)
        {
            string[] value = new string[count];
            for (int i = 0; i < value.Length; i++)
                value[i] = ReadString(format, fixedLength);

            return value;
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

            if (mSwap)
                obj = EndiannessHelper.Swap(obj);

            return obj;
        }

        public T[] ReadStruct<T>(int count)
            where T : struct
        {
            T[] objects = new T[count];

            int typeSize = Marshal.SizeOf<T>();
            var bytes = ReadBytes(typeSize * count);

            unsafe
            {
                fixed (byte* ptr = bytes)
                {
                    for (int i = 0; i < objects.Length; i++)
                    {
                        if (mSwap)
                            objects[i] = EndiannessHelper.Swap(Marshal.PtrToStructure<T>((IntPtr)(ptr + (i * typeSize))));
                        else
                            objects[i] = Marshal.PtrToStructure<T>((IntPtr)(ptr + (i * typeSize)));
                    }
                }
            }

            return objects;
        }
    }
}
