using System;

namespace AtlusScriptLibrary.Common.IO
{
    public static unsafe class Unsafe
    {
        public static TDest ReinterpretCast<TSource, TDest>(TSource source)
        {
            var sourceRef = __makeref(source);
            var dest = default(TDest);
            var destRef = __makeref(dest);
            *(IntPtr*)&destRef = *((IntPtr*)&sourceRef);
            return __refvalue(destRef, TDest);
        }

        public static void ReinterpretCast<TSource, TDest>(TSource source, out TDest destination)
        {
            var sourceRef = __makeref(source);
            var dest = default(TDest);
            var destRef = __makeref(dest);
            *(IntPtr*)&destRef = *((IntPtr*)&sourceRef);
            destination = __refvalue(destRef, TDest);
        }

        /*
        // Int16
        public static void ReinterpretCast(short value, out sbyte outValue, int offset = 0)
        {
            outValue = *((sbyte*)&value + offset);
        }

        public static void ReinterpretCast(short value, out byte outValue, int offset = 0)
        {
            outValue = *((byte*)&value + offset);
        }

        // UInt16
        public static void ReinterpretCast(ushort value, out sbyte outValue, int offset = 0)
        {
            outValue = *((sbyte*)&value + offset);
        }

        public static void ReinterpretCast(ushort value, out byte outValue, int offset = 0)
        {
            outValue = *((byte*)&value + offset);
        }

        // Int32
        public static void ReinterpretCast(int value, out sbyte outValue, int offset = 0)
        {
            outValue = *((sbyte*)&value + offset);
        }

        public static void ReinterpretCast(int value, out byte outValue, int offset = 0)
        {
            outValue = *((byte*)&value + offset);
        }

        public static void ReinterpretCast(int value, out short outValue, int offset = 0)
        {
            outValue = *((short*)&value + offset);
        }

        public static void ReinterpretCast(int value, out ushort outValue, int offset = 0)
        {
            outValue = *((ushort*)&value + offset);
        }

        public static void ReinterpretCast(int value, out float outValue)
        {
            outValue = *(float*)&value;
        }

        // UInt32
        public static void ReinterpretCast(uint value, out sbyte outValue, int offset = 0)
        {
            outValue = *((sbyte*)&value + offset);
        }

        public static void ReinterpretCast(uint value, out byte outValue, int offset = 0)
        {
            outValue = *((byte*)&value + offset);
        }

        public static void ReinterpretCast(uint value, out short outValue, int offset = 0)
        {
            outValue = *((short*)&value + offset);
        }

        public static void ReinterpretCast(uint value, out ushort outValue, int offset = 0)
        {
            outValue = *((ushort*)&value + offset);
        }

        public static void ReinterpretCast(uint value, out float outValue)
        {
            outValue = *(float*)&value;
        }

        // Single
        public static void ReinterpretCast(float value, out sbyte outValue, int offset = 0)
        {
            outValue = *((sbyte*)&value + offset);
        }

        public static void ReinterpretCast(float value, out byte outValue, int offset = 0)
        {
            outValue = *((byte*)&value + offset);
        }

        public static void ReinterpretCast(float value, out short outValue, int offset = 0)
        {
            outValue = *((short*)&value + offset);
        }

        public static void ReinterpretCast(float value, out ushort outValue, int offset = 0)
        {
            outValue = *((ushort*)&value + offset);
        }

        public static void ReinterpretCast(float value, out int outValue)
        {
            outValue = *(int*)&value;
        }

        public static void ReinterpretCast(float value, out uint outValue)
        {
            outValue = *(uint*)&value;
        }
        */
    }
}
