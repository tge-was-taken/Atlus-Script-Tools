using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V1;

public static class MessageScriptBinaryTokenParser
{
    public static bool TryParseTokens(IReadOnlyList<byte> buffer, ref int bufferIndex, out List<IToken> tokens, FormatVersion version, Encoding encoding)
    {
        byte b = buffer[bufferIndex++];
        tokens = new List<IToken>();

        // Check if the current byte signifies a function
        if (b == 0)
        {
            tokens = null;
            return false;
        }
        if (b == NewLineToken.ASCIIValue)
        {
            tokens.Add(new NewLineToken());
        }
        else if (IsFunctionToken(b, version))
        {
            tokens.Add(ParseFunctionToken(b, buffer, ref bufferIndex, version));
        }
        else
        {
            tokens.AddRange(ParseTextTokens(b, buffer, ref bufferIndex, encoding));
        }

        return true;
    }


    private static bool IsFunctionToken(byte b, FormatVersion version)
    {
        if (version == FormatVersion.Version1Reload)
        {
            return b == 0xFE;
        }
        else
        {
            return (b & 0xF0) == 0xF0;
        }
    }

    private static FunctionToken ParseFunctionToken(byte b, IReadOnlyList<byte> buffer, ref int bufferIndex, FormatVersion version)
    {
        int first = (version == FormatVersion.Version1Reload) ? buffer[bufferIndex++] : b;
        int functionId = (first << 8) | buffer[bufferIndex++];
        int functionTableIndex = (functionId & 0xE0) >> 5;
        int functionIndex = (functionId & 0x1F);

        int functionArgumentByteCount;
        if (version == FormatVersion.Version1 || version == FormatVersion.Version1BigEndian || version == FormatVersion.Version1Reload)
        {
            functionArgumentByteCount = ((((functionId >> 8) & 0xF) - 1) * 2);
        }
        else if (version == FormatVersion.Version1DDS)
        {
            functionArgumentByteCount = ((functionId >> 8) & 0xF);
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(version));
        }

        var functionArguments = new ushort[functionArgumentByteCount / 2];

        for (int i = 0; i < functionArguments.Length; i++)
        {
            byte firstByte = (byte)(buffer[bufferIndex++] - 1);
            byte secondByte = 0;
            byte secondByteAux = buffer[bufferIndex++];

            //if (secondByteAux != 0xFF)
            {
                secondByte = (byte)(secondByteAux - 1);
            }

            functionArguments[i] = (ushort)((firstByte & ~0xFF00) | ((secondByte << 8) & 0xFF00));
        }
        var bAddIdentifierType = (version == FormatVersion.Version1Reload) ? true : false;
        return new FunctionToken(functionTableIndex, functionIndex, bAddIdentifierType, functionArguments);
    }

    private static IEnumerable<IToken> ParseTextTokens(byte b, IReadOnlyList<byte> buffer, ref int bufferIndex, Encoding encoding)
    {
        var accumulatedText = new List<byte>();
        var charBytes = new byte[2];
        var tokens = new List<IToken>();
        byte b2;
        while (true)
        {
            if (encoding == Encoding.UTF8)
            {
                accumulatedText.Add(b);
                if (b > 0xC0) // read 2 bytes
                {
                    b2 = buffer[bufferIndex++];
                    accumulatedText.Add(b2);
                    if (b > 0xE0) // read 3 bytes
                    {
                        var b3 = buffer[bufferIndex++];
                        accumulatedText.Add(b3);
                        if (b > 0xF0) // read 4 bytes
                        {
                            var b4 = buffer[bufferIndex++];
                            accumulatedText.Add(b4);
                        }
                    }
                }
            }
            else // Atlus and Shift-JIS
            {
                if ((b & 0x80) == 0x80)
                {
                    b2 = buffer[bufferIndex++];
                    accumulatedText.Add(b);
                    accumulatedText.Add(b2);
                }
                else
                {
                    // Read one
                    accumulatedText.Add(b);
                }
            }

            // Check for any condition that would end the sequence of text characters
            if (bufferIndex == buffer.Count)
                break;

            b = buffer[bufferIndex];

            if (b == 0 || b == NewLineToken.ASCIIValue || (b & 0xF0) == 0xF0)
            {
                break;
            }

            bufferIndex++;
        }

        var accumulatedTextBuffer = accumulatedText.ToArray();
        var stringBuilder = new StringBuilder();

        void FlushStringBuilder()
        {
            // There was some proper text previously, so make sure we add it first
            if (stringBuilder.Length != 0)
            {
                tokens.Add(new StringToken(stringBuilder.ToString()));
                stringBuilder.Clear();
            }
        }

        void AddToken(CodePointToken token)
        {
            FlushStringBuilder();
            tokens.Add(token);
        }

        if (encoding == Encoding.UTF8)
        {
            stringBuilder.Append(Encoding.UTF8.GetString(accumulatedTextBuffer));
        }
        else
        {
            for (int i = 0; i < accumulatedTextBuffer.Length; i++)
            {
                byte high = accumulatedTextBuffer[i];
                if ((high & 0x80) == 0x80)
                {
                    byte low = accumulatedTextBuffer[++i];

                    if (encoding != null && !encoding.IsSingleByte)
                    {
                        // Get decoded characters
                        charBytes[0] = high;
                        charBytes[1] = low;

                        // Check if it's an unmapped character -> make it a code point
                        var chars = encoding.GetChars(charBytes);
                        Trace.Assert(chars.Length > 0);

                        if (chars[0] == 0)
                        {
                            AddToken(new CodePointToken(high, low));
                        }
                        else
                        {
                            foreach (char c in chars)
                            {
                                stringBuilder.Append(c);
                            }
                        }
                    }
                    else
                    {
                        AddToken(new CodePointToken(high, low));
                    }
                }
                else
                {
                    stringBuilder.Append((char)high);
                }
            }
        }

        FlushStringBuilder();

        return tokens;
    }

}
