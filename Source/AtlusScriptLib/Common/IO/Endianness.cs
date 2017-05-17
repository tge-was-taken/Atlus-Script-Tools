using System;
using System.Linq;

namespace AtlusScriptLib.Common.IO
{
    public enum Endianness
    {
        LittleEndian,
        BigEndian
    }

    public static class EndiannessHelper
    {
        public static Endianness SystemEndianness
        {
            get
            {
                if (BitConverter.IsLittleEndian)
                    return Endianness.LittleEndian;
                else
                    return Endianness.BigEndian;
            }
        }

        public static short SwapEndianness(short value)
        {
            return (short)((value << 8) | ((value >> 8) & 0xFF));
        }

        public static ushort SwapEndianness(ushort value)
        {
            return (ushort)((value << 8) | (value >> 8));
        }

        public static int SwapEndianness(int value)
        {
            value = (int)((value << 8) & 0xFF00FF00) | ((value >> 8) & 0xFF00FF);
            return (value << 16) | ((value >> 16) & 0xFFFF);
        }

        public static uint SwapEndianness(uint value)
        {
            value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0xFF00FF);
            return (value << 16) | (value >> 16);
        }

        public static long SwapEndianness(long value)
        {
            value = (long)(((ulong)(value << 8) & 0xFF00FF00FF00FF00UL) | ((ulong)(value >> 8) & 0x00FF00FF00FF00FFUL));
            value = (long)(((ulong)(value << 16) & 0xFFFF0000FFFF0000UL) | ((ulong)(value >> 16) & 0x0000FFFF0000FFFFUL));
            return (long)((ulong)(value << 32) | ((ulong)(value >> 32) & 0xFFFFFFFFUL));
        }

        public static ulong SwapEndianness(ulong value)
        {
            value = ((value << 8) & 0xFF00FF00FF00FF00UL ) | ((value >> 8) & 0x00FF00FF00FF00FFUL );
            value = ((value << 16) & 0xFFFF0000FFFF0000UL ) | ((value >> 16) & 0x0000FFFF0000FFFFUL );
            return (value << 32) | (value >> 32);
        }

        public unsafe static float SwapEndianness(float value)
        {
            return Unsafe.ReinterpretCast<uint, float>(
                SwapEndianness(Unsafe.ReinterpretCast<float, uint>(value))
            );
        }

        public unsafe static double SwapEndianness(double value)
        {
            return Unsafe.ReinterpretCast<ulong, double>(
                SwapEndianness(Unsafe.ReinterpretCast<double, ulong>(value))
            );
        }

        public unsafe static decimal SwapEndianness(decimal value)
        {
            ulong* pData = stackalloc ulong[2];

            *pData = SwapEndianness(*(ulong*)&value);
            pData++;
            *pData = SwapEndianness(*((ulong*)&value + 16));

            return *(decimal*)pData;
        }

        private static object SwapEndiannessPrimitive(Type type, object value)
        {
            switch (Type.GetTypeCode(type))
            {
                case TypeCode.Boolean:
                case TypeCode.Byte:
                case TypeCode.SByte:
                    return value;

                case TypeCode.Int16:
                    return SwapEndianness((short)value);

                case TypeCode.UInt16:
                    return SwapEndianness((ushort)value);

                case TypeCode.Int32:
                    return SwapEndianness((int)value);

                case TypeCode.UInt32:
                    return SwapEndianness((uint)value);

                case TypeCode.Int64:
                    return SwapEndianness((long)value);

                case TypeCode.UInt64:
                    return SwapEndianness((ulong)value);

                case TypeCode.Single:
                    return SwapEndianness((float)value);

                case TypeCode.Double:
                    return SwapEndianness((double)value);

                case TypeCode.Decimal:
                    return SwapEndianness((decimal)value);

                default:
                    throw new NotImplementedException();
            }
        }

        private static object SwapEndiannessRecursive(object obj, Type type)
        {
            if (type.IsArray)
            {
                var array = (Array)obj;
                var elemType = type.GetElementType();

                for (int i = 0; i < array.Length; i++)
                {
                    array.SetValue(SwapEndiannessRecursive(array.GetValue(i), elemType), i);
                }

                return array;
            }
            else if (type.IsClass)
            {
                SwapEndianness(obj, type);
                return obj;
            }
            else if (type.IsEnum)
            {
                return SwapEndiannessRecursive(obj, type.GetEnumUnderlyingType());
            }
            else if (type.IsGenericType)
            {
                throw new NotImplementedException();
            }
            else if (type.IsInterface)
            {
                throw new NotImplementedException();
            }
            else if (type.IsPointer)
            {
                throw new NotImplementedException();
            }
            else if (type.IsPrimitive)
            {
                return SwapEndiannessPrimitive(type, obj);
            }
            else if (type.IsValueType)
            {
                SwapEndianness(obj, type);
                return obj;
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        private static object SwapEndianness(object obj, Type type)
        {         
            var fields = type.GetFields().ToList();

            // Handle tuples
            //if (type.GetCustomAttribute<StructLayoutAttribute>()?.Value == LayoutKind.Explicit)
            //{
            //    var fieldOffsetDictionary = new Dictionary<int, List<FieldInfo>>();
            //    for (int i = 0; i < fields.Count; i++)
            //    {
            //        var attrib = fields[i].GetCustomAttribute<FieldOffsetAttribute>();

            //        if (attrib != null)
            //        {
            //            if (!fieldOffsetDictionary.ContainsKey(attrib.Value))
            //                fieldOffsetDictionary[attrib.Value] = new List<FieldInfo>();

            //            fieldOffsetDictionary[attrib.Value].Add(fields[i]);
            //        }
            //    }

            //    if (fieldOffsetDictionary.Count > 0)
            //    {
            //        int lastBiggestFieldEndIndex = -1;
            //        foreach (var fieldOffset in fieldOffsetDictionary.Keys)
            //        {
            //            var fieldsWithOffsets = fieldOffsetDictionary[fieldOffset];
            //            int biggestFieldEndIndex = -1;

            //            var biggestField = fieldsWithOffsets.MaxBy(x =>
            //            {
            //                var val = x.GetValue(obj);
            //                var size = 0;

            //                if (x.FieldType.IsEnum)
            //                    size = Marshal.SizeOf(x.FieldType.GetEnumUnderlyingType());
            //                else
            //                    size = Marshal.SizeOf(val);

            //                if (fieldOffset + size > biggestFieldEndIndex)
            //                    biggestFieldEndIndex = fieldOffset + size;

            //                return size;
            //            });

            //            if (lastBiggestFieldEndIndex >= biggestFieldEndIndex)
            //            {
            //                for (int i = 0; i < fieldsWithOffsets.Count; i++)
            //                {
            //                    fields.Remove(fieldsWithOffsets[i]);
            //                }
            //            }
            //            else
            //            {
            //                for (int i = 0; i < fieldsWithOffsets.Count; i++)
            //                {
            //                    if (fieldsWithOffsets[i] != biggestField)
            //                        fields.Remove(fieldsWithOffsets[i]);
            //                }

            //                lastBiggestFieldEndIndex = biggestFieldEndIndex;
            //            }
            //        }
            //    }
            //}

            foreach (var field in fields)
            {
                if (field.IsLiteral || field.IsStatic)
                    continue;

                field.SetValue(obj, SwapEndiannessRecursive(field.GetValue(obj), field.FieldType));
            }

            return obj;
        }

        public static T SwapEndianness<T>(T obj)
        {
            object temp = obj;
            temp = SwapEndianness(temp, typeof(T));
            return (T)temp;
        }
    }
}
