using AtlusScriptLibrary.Common.Text.Encodings;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2;

public static class MessageScriptBinaryV2TokenParser
{
    public static bool TryParseTokens(IReadOnlyList<byte> buffer, ref int bufferIndex, out List<IToken> tokens, FormatVersion version, Encoding encoding)
    {
        static bool IsUnicodeCharacter(ushort c)
        {
            return ((ushort)(c + 0x2800)) > 0x7FF;
        }
        static char MapToUnicodeCharacter(ushort c, Encoding encoding)
        {
            if (encoding is CustomUnicodeEncoding cue)
            {
                if (cue.CustomCodeToChar.TryGetValue(c, out var ch))
                    return ch;
            }
            return (char)c;
        }
        static bool IsSafeCharacter(ushort c, Encoding encoding)
        {
            var result = (c >= 21 && c <= 126);
            if (encoding is CustomUnicodeEncoding cue)
                result = result || cue.CustomCodeToChar.ContainsKey(c);
            return result;
        }

        tokens = [];

        if (!TokenParserReaderHelper.TryReadUInt16(buffer, ref bufferIndex, version, out var c))
            return false;

        if (IsUnicodeCharacter(c))
        {
            if (!IsSafeCharacter(c, encoding))
            {
                tokens.Add(new CodePointToken((byte)((c & 0xFF00) >> 8), (byte)(c & 0xFF)));
            }
            else
            {
                var stringBuilder = new StringBuilder();
                stringBuilder.Append(MapToUnicodeCharacter(c, encoding));
                while (true)
                {
                    if (!TokenParserReaderHelper.TryReadUInt16(buffer, ref bufferIndex, version, out c))
                        break;
                    if (!(IsUnicodeCharacter(c) && IsSafeCharacter(c, encoding)))
                    {
                        bufferIndex -= 2;
                        break;
                    }
                    stringBuilder.Append(MapToUnicodeCharacter(c, encoding));
                }
                tokens.Add(new StringToken(stringBuilder.ToString()));
            }
        }
        else
        {
            var args = new List<ushort>();

            int argCount;
            if (c == 0xD091)
            {
                argCount = 1;
            }
            else
            {
                argCount = (c >> 8) & 7;
            }

            if (c == 0xD828)
            {
                while (true)
                {
                    if (!TokenParserReaderHelper.TryReadUInt16(buffer, ref bufferIndex, version, out var temp))
                        break;

                    if (temp == 0xD829)
                    {
                        tokens.Add(new FunctionToken(0, temp, false));
                        break;
                    }
                    else
                    {
                        args.Add(temp);
                    }
                }
            }
            else
            {
                for (int i = 0; i < argCount; i++)
                {
                    if (!TokenParserReaderHelper.TryReadUInt16(buffer, ref bufferIndex, version, out var temp))
                        break;
                    args.Add(temp);
                }
            }

            tokens.Add(new FunctionToken(0, c, args, false));
        }

        return true;
    }

}
