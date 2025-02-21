using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AtlusScriptLibrary.Common.Text.Encodings;

public abstract class CustomUnicodeEncoding : Encoding
{
    private readonly Dictionary<char, ushort> _charToCode;
    private readonly Dictionary<ushort, char> _codeToChar;
    private readonly Encoding _baseEncoding;
    private readonly bool _isBigEndian;

    protected CustomUnicodeEncoding(bool isBigEndian, Dictionary<ushort, char> codeToCharMap)
    {
        _baseEncoding = isBigEndian ? BigEndianUnicode : Unicode;
        _isBigEndian = isBigEndian;
        _codeToChar = codeToCharMap;
        _charToCode = _codeToChar.ToDictionary(x => x.Value, x => x.Key);
    }

    public IReadOnlyDictionary<char, ushort> CharToCustomCode => _charToCode;
    public IReadOnlyDictionary<ushort, char> CustomCodeToChar => _codeToChar;
    public abstract CustomUnicodeEncoding GetEncodingForEndianness(bool isBigEndian);

    public override int GetByteCount(char[] chars, int index, int count)
        => _baseEncoding.GetByteCount(chars, index, count);

    public override int GetBytes(char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex)
    {
        int bytesWritten = 0;
        for (int i = 0; i < charCount; i++)
        {
            char currentChar = chars[charIndex + i];
            if (_charToCode.TryGetValue(currentChar, out ushort code))
            {
                if (_isBigEndian)
                    BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(byteIndex + bytesWritten), code);
                else
                    BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(byteIndex + bytesWritten), code);

                bytesWritten += 2;
            }
            else
            {
                // Fallback to base encoding for unmapped characters
                bytesWritten += _baseEncoding.GetBytes(chars, charIndex + i, 1, bytes, byteIndex + bytesWritten);
            }
        }
        return bytesWritten;
    }

    public override int GetCharCount(byte[] bytes, int index, int count)
        => _baseEncoding.GetCharCount(bytes, index, count);

    public override int GetChars(byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex)
    {
        int charsWritten = 0;
        char[] fallbackChar = new char[1];
        for (int i = 0; i < byteCount; i += 2)
        {
            ushort code = _isBigEndian
                ? BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(byteIndex + i))
                : BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(byteIndex + i));

            if (_codeToChar.TryGetValue(code, out char decodedChar))
            {
                chars[charIndex + charsWritten++] = decodedChar;
            }
            else
            {
                // Fallback to base decoding for unmapped codes
                fallbackChar[0] = default;
                _baseEncoding.GetChars(bytes, byteIndex + i, 2, fallbackChar, 0);
                chars[charIndex + charsWritten++] = fallbackChar[0];
            }
        }
        return charsWritten;
    }

    public override int GetMaxByteCount(int charCount)
        => _baseEncoding.GetMaxByteCount(charCount);

    public override int GetMaxCharCount(int byteCount)
        => _baseEncoding.GetMaxCharCount(byteCount);
}