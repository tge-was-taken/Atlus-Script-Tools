using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace AtlusScriptLibrary.Common.IO;

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
            return Endianness.BigEndian;
        }
    }

    public static short Swap(short value)
    {
        return (short)((value << 8) | ((value >> 8) & 0xFF));
    }

    public static void Swap(ref short value)
    {
        value = Swap(value);
    }

    public static ushort Swap(ushort value)
    {
        return (ushort)((value << 8) | (value >> 8));
    }

    public static void Swap(ref ushort value)
    {
        value = Swap(value);
    }

    public static int Swap(int value)
    {
        value = (int)((value << 8) & 0xFF00FF00) | ((value >> 8) & 0xFF00FF);
        return (value << 16) | ((value >> 16) & 0xFFFF);
    }

    public static void Swap(ref int value)
    {
        value = Swap(value);
    }

    public static uint Swap(uint value)
    {
        value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0xFF00FF);
        return (value << 16) | (value >> 16);
    }

    public static void Swap(ref uint value)
    {
        value = Swap(value);
    }

    public static long Swap(long value)
    {
        value = (long)(((ulong)(value << 8) & 0xFF00FF00FF00FF00UL) | ((ulong)(value >> 8) & 0x00FF00FF00FF00FFUL));
        value = (long)(((ulong)(value << 16) & 0xFFFF0000FFFF0000UL) | ((ulong)(value >> 16) & 0x0000FFFF0000FFFFUL));
        return (long)((ulong)(value << 32) | ((ulong)(value >> 32) & 0xFFFFFFFFUL));
    }

    public static void Swap(ref long value)
    {
        value = Swap(value);
    }

    public static ulong Swap(ulong value)
    {
        value = ((value << 8) & 0xFF00FF00FF00FF00UL) | ((value >> 8) & 0x00FF00FF00FF00FFUL);
        value = ((value << 16) & 0xFFFF0000FFFF0000UL) | ((value >> 16) & 0x0000FFFF0000FFFFUL);
        return (value << 32) | (value >> 32);
    }

    public static void Swap(ref ulong value)
    {
        value = Swap(value);
    }

    public static float Swap(float value)
    {
        return Unsafe.ReinterpretCast<uint, float>(
            Swap(Unsafe.ReinterpretCast<float, uint>(value))
        );
    }

    public static void Swap(ref float value)
    {
        value = Swap(value);
    }

    public static double Swap(double value)
    {
        return Unsafe.ReinterpretCast<ulong, double>(
            Swap(Unsafe.ReinterpretCast<double, ulong>(value))
        );
    }

    public static void Swap(ref double value)
    {
        value = Swap(value);
    }

    public unsafe static decimal Swap(decimal value)
    {
        ulong* pData = stackalloc ulong[2];

        *pData = Swap(*(ulong*)&value);
        pData++;
        *pData = Swap(*((ulong*)&value + 16));

        return *(decimal*)pData;
    }

    public static void Swap(ref decimal value)
    {
        value = Swap(value);
    }

    // SwapRecursive walks field, element and enum underlying types, which the trimmer
    // cannot follow transitively. Everything reached this way is a primitive, an enum or
    // an array of those, none of which have fields that trimming could remove.
    [UnconditionalSuppressMessage("Trimming", "IL2072", Justification = "Nested types reached here are primitives, enums or arrays of those.")]
    private static object SwapRecursive(object obj, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.NonPublicConstructors)] Type type)
    {
        if (type.IsArray)
        {
            var array = (Array)obj;
            var elemType = type.GetElementType();

            for (int i = 0; i < array.Length; i++)
            {
                array.SetValue(SwapRecursive(array.GetValue(i), elemType), i);
            }

            return array;
        }
        if (type.IsClass)
        {
            Swap(obj, type);
            return obj;
        }
        if (type.IsEnum)
        {
            // Unbox to the underlying primitive as well as switching type, or the swap
            // below sees a boxed enum it has no case for.
            var underlyingType = type.GetEnumUnderlyingType();
            return SwapRecursive(Convert.ChangeType(obj, underlyingType), underlyingType);
        }
        if (type.IsGenericType)
        {
            throw new NotImplementedException();
        }
        if (type.IsInterface)
        {
            throw new NotImplementedException();
        }
        if (type.IsPointer)
        {
            throw new NotImplementedException();
        }
        if (type.IsPrimitive)
        {
            return SwapPrimitive(obj);
        }
        if (type.IsValueType)
        {
            Swap(obj, type);
            return obj;
        }
        throw new NotImplementedException();
    }

    private static object SwapPrimitive(object obj) => obj switch
    {
        short v => Swap(v),
        ushort v => Swap(v),
        int v => Swap(v),
        uint v => Swap(v),
        long v => Swap(v),
        ulong v => Swap(v),
        float v => Swap(v),
        double v => Swap(v),
        decimal v => Swap(v),
        // Single-byte and non-numeric primitives have no byte order to swap.
        byte or sbyte or bool or char => obj,
        _ => throw new NotSupportedException($"Cannot byte swap primitive type '{obj.GetType()}'")
    };

    [UnconditionalSuppressMessage("Trimming", "IL2072", Justification = "Nested types reached here are primitives, enums or arrays of those.")]
    private static object Swap(object obj, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.NonPublicConstructors)] Type type)
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

            field.SetValue(obj, SwapRecursive(field.GetValue(obj), field.FieldType));
        }

        return obj;
    }

    public static T Swap<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.NonPublicConstructors)] T>(T obj)
    {
        object temp = obj;
        temp = Swap(temp, typeof(T));
        return (T)temp;
    }

    public static void Swap<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.NonPublicConstructors)] T>(ref T obj)
    {
        obj = Swap(obj);
    }
}
