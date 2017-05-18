using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace AtlusScriptLib.Common.IO
{
    public class EndianBinaryWriter : BinaryWriter
    {
        private StringBuilder   mStringBuilder;
        private Endianness      mEndianness;
        private bool            mSwap;
        private Encoding        mEncoding;
        private Stack<long>     mPosStack;

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

        public EndianBinaryWriter(Stream input, Endianness endianness)
            : base(input)
        {
            Init(Encoding.Default, endianness);
        }

        public EndianBinaryWriter(Stream input, Encoding encoding, Endianness endianness)
            : base(input, encoding)
        {
            Init(encoding, endianness);
        }

        public EndianBinaryWriter(Stream input, Encoding encoding, bool leaveOpen, Endianness endianness)
            : base(input, encoding, leaveOpen)
        {
            Init(encoding, endianness);
        }

        private void Init(Encoding encoding, Endianness endianness)
        {
            mStringBuilder = new StringBuilder();
            mEndianness = endianness;
            mEncoding = encoding;
            mPosStack = new Stack<long>();
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

        public void PushPosition()
        {
            mPosStack.Push(Position);
        }

        public long PopPosition()
        {
            return mPosStack.Pop();
        }

        public void SeekPopPosition()
        {
            SeekBegin(PopPosition());
        }

        public override void Write(short value)
        {
            if (mSwap)
                Write(EndiannessHelper.SwapEndianness(value));
            else
                base.Write(value);
        }

        public void Write(short[] values)
        {
            foreach (var value in values)
                Write(value);
        }

        public override void Write(ushort value)
        {
            if (mSwap)
                Write(EndiannessHelper.SwapEndianness(value));
            else
                base.Write(value);
        }

        public void Write(ushort[] values)
        {
            foreach (var value in values)
                Write(value);
        }

        public override void Write(int value)
        {
            if (mSwap)
                Write(EndiannessHelper.SwapEndianness(value));
            else
                base.Write(value);
        }

        public void Write(int[] values)
        {
            foreach (var value in values)
                Write(value);
        }

        public override void Write(uint value)
        {
            if (mSwap)
                Write(EndiannessHelper.SwapEndianness(value));
            else
                base.Write(value);
        }

        public void Write(uint[] values)
        {
            foreach (var value in values)
                Write(value);
        }

        public override void Write(long value)
        {
            if (mSwap)
                Write(EndiannessHelper.SwapEndianness(value));
            else
                base.Write(value);
        }

        public void Write(long[] values)
        {
            foreach (var value in values)
                Write(value);
        }

        public override void Write(ulong value)
        {
            if (mSwap)
                Write(EndiannessHelper.SwapEndianness(value));
            else
                base.Write(value);
        }

        public void Write(ulong[] values)
        {
            foreach (var value in values)
                Write(value);
        }

        public override void Write(float value)
        {
            if (mSwap)
                Write(EndiannessHelper.SwapEndianness(value));
            else
                base.Write(value);
        }

        public void Write(float[] values)
        {
            foreach (var value in values)
                Write(value);
        }

        public override void Write(decimal value)
        {
            if (mSwap)
                Write(EndiannessHelper.SwapEndianness(value));
            else
                base.Write(value);
        }

        public void Write(decimal[] values)
        {
            foreach (var value in values)
                Write(value);
        }

        public void Write(string value, StringBinaryFormat format, int fixedLength = -1)
        {
            switch (format)
            {
                case StringBinaryFormat.NullTerminated:
                    {
                        Write(mEncoding.GetBytes(value));

                        for (int i = 0; i < mEncoding.GetMaxByteCount(1); i++)
                            Write((byte)0);
                    }
                    break;
                case StringBinaryFormat.FixedLength:
                    {
                        if (fixedLength == -1)
                        {
                            throw new ArgumentException("Fixed length must be provided if format is set to fixed length", nameof(fixedLength));
                        }

                        var bytes = mEncoding.GetBytes(value);
                        if (bytes.Length > fixedLength)
                        {
                            throw new ArgumentException("Provided string is longer than fixed length", nameof(value));
                        }

                        Write(bytes);
                        fixedLength -= bytes.Length;

                        while (fixedLength > 0)
                            Write((byte)0);
                    }
                    break;

                case StringBinaryFormat.PrefixedLength8:
                    {
                        Write((byte)value.Length);
                        Write(mEncoding.GetBytes(value));
                    }
                    break;

                case StringBinaryFormat.PrefixedLength16:
                    {
                        Write((ushort)value.Length);
                        Write(mEncoding.GetBytes(value));
                    }
                    break;

                case StringBinaryFormat.PrefixedLength32:
                    {
                        Write((uint)value.Length);
                        Write(mEncoding.GetBytes(value));
                    }
                    break;

                default:
                    throw new ArgumentException("Invalid format specified", nameof(format));
            }
        }

        public void Write<T>(ref T value)
            where T : struct
        {
            // Allocate bytes for struct
            var bytes = new byte[Marshal.SizeOf<T>()];

            unsafe
            {
                fixed (byte* ptr = bytes)
                {
                    // Marshal the structure into the allocated byte array
                    if (mSwap)
                        Marshal.StructureToPtr(EndiannessHelper.SwapEndianness(value), (IntPtr)ptr, true);
                    else
                        Marshal.StructureToPtr(value, (IntPtr)ptr, true);
                }
            }

            // Lastly write out the bytes
            Write(bytes);
        }

        public void Write<T>(T[] value)
            where T : struct
        {
            // Allocate bytes for struct
            int typeSize = Marshal.SizeOf<T>();
            var bytes = new byte[typeSize * value.Length];

            unsafe
            {
                fixed (byte* ptr = bytes)
                {
                    for (int i = 0; i < value.Length; i++)
                    {
                        // Marshal the structure into the allocated byte array
                        if (mSwap)
                            Marshal.StructureToPtr(EndiannessHelper.SwapEndianness(value), (IntPtr)(ptr + (i * typeSize)), true);
                        else
                            Marshal.StructureToPtr(value, (IntPtr)(ptr + (i * typeSize)), true);
                    }             
                }
            }

            // Lastly write out the bytes
            Write(bytes);
        }
    }
}
