using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V3;

public static class Bm2BinaryTokenParser
{
    public static bool TryParseTokens(
        IReadOnlyList<byte> buffer,
        ref int bufferIndex,
        out List<IToken> tokens,
        FormatVersion version,
        Encoding encoding)
    {
        tokens = new List<IToken>();
        byte currentByte = buffer[bufferIndex];

        // Function token
        if (currentByte == 0xFF)
        {
            bufferIndex++;
            if (!TryParseFunctionToken(buffer, ref bufferIndex, out var functionToken, version))
                return false;

            tokens.Add(functionToken);
        }
        // Plain text
        else
        {
            if (!TryParsePlainText(buffer, ref bufferIndex, encoding, tokens))
                return false;
        }

        return true;
    }

    private static bool TryParseFunctionToken(
        IReadOnlyList<byte> buffer,
        ref int bufferIndex,
        out FunctionToken token,
        FormatVersion version)
    {
        token = default;

        if (!TokenParserReaderHelper.TryReadUInt16(buffer, ref bufferIndex, version, out ushort arg1) ||
            !TokenParserReaderHelper.TryReadUInt16(buffer, ref bufferIndex, version, out ushort arg2))
            return true;

        // If functionId > 12, perform special handling
        if (arg1 > 12)
        {
            throw new NotImplementedException("functionId > 12");

            for (int i = 0; i < arg2; i++)
            {
                if (bufferIndex >= buffer.Count)
                    break;

                byte skipType = buffer[bufferIndex++];
                if (skipType == 2)
                {
                    if (!TokenParserReaderHelper.TryReadUInt32(buffer, ref bufferIndex, version, out var offset))
                        break;

                    // Skipping 6 bytes at the offset
                    if (bufferIndex + 6 > buffer.Count)
                        break;

                    bufferIndex += 6;
                }
                else if (skipType == 1)
                {
                    // Skipping 6 bytes
                    if (bufferIndex + 6 > buffer.Count)
                        break;

                    bufferIndex += 6;
                }
                else
                {
                    break; // Unknown skip type
                }
            }

            return true;
        }
        else
        {
            int argCount = GetFunctionArgumentCount(arg1);
            List<ushort> arguments = new() { arg2 };
            if (argCount > 0)
            {
                for (int i = 0; i < argCount; i++)
                {
                    if (bufferIndex >= buffer.Count)
                        break;

                    arguments.Add(buffer[bufferIndex++]);
                }
            }
            token = new FunctionToken(0, arg1, arguments, false);
        }
        return true;
    }

    // TOOD: unharcode this if necessary
    private static int GetFunctionArgumentCount(ushort id)
    {
        return id switch
        {
            0 => -1,
            1 => 0,
            2 => 18,
            3 => 0,
            4 => 12,
            //4 => 6,
            5 => 18,
            6 => 6,
            7 => 0,
            8 => 0,
            9 => 6,
            10 => 0,
            11 => 18,
            12 => 12,
            //12 => 6,
            _ => throw new ArgumentOutOfRangeException(nameof(id), "Invalid function ID")
        };
    }

    private static bool TryParsePlainText(
        IReadOnlyList<byte> buffer,
        ref int bufferIndex,
        Encoding encoding,
        List<IToken> tokens)
    {
        while (bufferIndex < buffer.Count)
        {
            byte currentByte = buffer[bufferIndex];

            // Null terminator or function indicator ends the text
            if (currentByte == 0xFF)
                break;

            bufferIndex++;
            if (currentByte == 0)
            {
                tokens.Add(new NewLineToken());
                break;
            }

            // Handle multibyte
            if (currentByte >= 0x80)
            {
                if (bufferIndex >= buffer.Count)
                    break;

                byte nextByte = buffer[bufferIndex++];
                tokens.Add(new CodePointToken(currentByte, nextByte));
            }
            else if (currentByte >= 0x20 && currentByte <= 0x7E)
            {
                var stringBytes = new List<byte>() { currentByte };
                // Scan ahead 
                while (bufferIndex < buffer.Count)
                {
                    currentByte = buffer[bufferIndex];
                    if (currentByte == 0x00 || currentByte < 0x20 || currentByte >= 0x7E || currentByte == 0xFF)
                        break;
                    bufferIndex++;
                    stringBytes.Add(currentByte);
                }
                tokens.Add(new StringToken(encoding.GetString(stringBytes.ToArray())));
            }
            else
            {
                tokens.Add(new CodePointToken(currentByte));
            }
        }

        return true;
    }
}
