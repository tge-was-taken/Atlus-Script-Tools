using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

internal class TokenParserReaderHelper
{
    public static bool TryReadUInt32(IReadOnlyList<byte> buffer, ref int bufferIndex, FormatVersion version, out uint value)
    {
        value = default;
        if (bufferIndex + 4 > buffer.Count)
            return false;

        Span<byte> temp = stackalloc byte[4];
        temp[0] = buffer[bufferIndex++];
        temp[1] = buffer[bufferIndex++];
        temp[2] = buffer[bufferIndex++];
        temp[3] = buffer[bufferIndex++];
        value = version.HasFlag(FormatVersion.BigEndian)
            ? BinaryPrimitives.ReadUInt32BigEndian(temp)
            : BinaryPrimitives.ReadUInt32LittleEndian(temp);
        return true;
    }

    public static bool TryReadUInt16(IReadOnlyList<byte> buffer, ref int bufferIndex, FormatVersion version, out ushort value)
    {
        value = default;
        if (bufferIndex + 2 > buffer.Count)
            return false;
        Span<byte> temp = stackalloc byte[2];
        temp[0] = buffer[bufferIndex++];
        temp[1] = buffer[bufferIndex++];
        value = version.HasFlag(FormatVersion.BigEndian) ? BinaryPrimitives.ReadUInt16BigEndian(temp) : BinaryPrimitives.ReadUInt16LittleEndian(temp);
        return true;
    }

}
