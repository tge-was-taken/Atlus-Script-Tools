using System;
using System.Collections.Generic;

namespace AtlusScriptLibrary.Common;

// netstandard2.0 has neither Convert.ToHexString nor Enumerable.ToHashSet.
internal static class HexText
{
    private const string Digits = "0123456789ABCDEF";

    public static string ToHex(byte[] bytes)
    {
        var text = new char[bytes.Length * 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            text[i * 2] = Digits[bytes[i] >> 4];
            text[i * 2 + 1] = Digits[bytes[i] & 0xF];
        }

        return new string(text);
    }

    public static byte[] FromHex(string text)
    {
        var bytes = new byte[text.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(text.Substring(i * 2, 2), 16);

        return bytes;
    }

    public static HashSet<T> ToSet<T>(this IEnumerable<T> source) => new HashSet<T>(source);
}
