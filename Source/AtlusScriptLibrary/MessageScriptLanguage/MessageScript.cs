using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V1;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// This class represents a mutable message script that is designed to abstract away the format implementation details.
/// </summary>
public class MessageScript
{
    public static MessageScript FromBinary(IMessageScriptBinary binary, FormatVersion version = FormatVersion.Detect, Encoding encoding = null)
    {
        if (binary is MessageScriptBinary v1)
            return FromBinary(v1, version, encoding);
        else if (binary is MessageScriptBinaryV2 v2)
            return FromBinary(v2, version, encoding);
        else
            throw new NotSupportedException();
    }

    // TODO: maybe move the parsing functions to a seperate class
    /// <summary>
    /// Creates a <see cref="MessageScript"/> from a <see cref="MessageScriptBinary"/>.
    /// </summary>
    public static MessageScript FromBinary(MessageScriptBinary binary, FormatVersion version = FormatVersion.Detect, Encoding encoding = null)
    {
        if (binary == null)
            throw new ArgumentNullException(nameof(binary));

        if (binary.DialogHeaders == null)
            throw new ArgumentNullException(nameof(binary));

        // Create new script instance & set user id, format version
        var instance = new MessageScript
        {
            Id = binary.Header.UserId,
            FormatVersion = version == FormatVersion.Detect ? (FormatVersion)binary.FormatVersion : version,
            Encoding = encoding
        };

        // Convert the binary messages to their counterpart
        var labelOccurences = new Dictionary<string, int>();
        foreach (var messageHeader in binary.DialogHeaders)
        {
            IDialog message;
            IReadOnlyList<int> pageStartAddresses;
            IReadOnlyList<byte> buffer;
            int pageCount;

            switch (messageHeader.Kind)
            {
                case BinaryDialogKind.Message:
                    {
                        var binaryMessage = (BinaryMessageDialog)messageHeader.Data.Value;
                        pageStartAddresses = binaryMessage.PageStartAddresses;
                        buffer = binaryMessage.TextBuffer;
                        pageCount = binaryMessage.PageCount;

                        // check for duplicates
                        var name = ResolveName(labelOccurences, binaryMessage.Name);

                        if (binaryMessage.SpeakerId == 0xFFFF)
                        {
                            message = new MessageDialog(name);
                        }
                        else if ((binaryMessage.SpeakerId & 0x8000) == 0x8000)
                        {
                            Trace.WriteLine(binaryMessage.SpeakerId.ToString("X4"));

                            message = new MessageDialog(name, new VariableSpeaker(binaryMessage.SpeakerId & 0x0FFF));
                        }
                        else
                        {
                            if (binary.SpeakerTableHeader.SpeakerNameArray.Value == null)
                                throw new InvalidDataException("Speaker name array is null while being referenced");

                            TokenText speakerName = null;
                            if (binaryMessage.SpeakerId < binary.SpeakerTableHeader.SpeakerCount)
                            {
                                speakerName = ParseSpeakerText(binary.SpeakerTableHeader.SpeakerNameArray
                                    .Value[binaryMessage.SpeakerId].Value, instance.FormatVersion, encoding == null ? Encoding.ASCII : encoding);
                            }

                            message = new MessageDialog(name, new NamedSpeaker(speakerName));
                        }
                    }
                    break;

                case BinaryDialogKind.Selection:
                    {
                        var binaryMessage = (BinarySelectionDialog)messageHeader.Data.Value;
                        pageStartAddresses = binaryMessage.OptionStartAddresses;
                        buffer = binaryMessage.TextBuffer;
                        pageCount = binaryMessage.OptionCount;
                        var name = ResolveName(labelOccurences, binaryMessage.Name);
                        message = new SelectionDialog(name, (SelectionDialogPattern)binaryMessage.Pattern);
                    }
                    break;

                default:
                    throw new InvalidDataException("Unknown message type");
            }

            if (pageCount != 0)
            {
                // Parse the line data
                ParsePages(message, pageStartAddresses, buffer, instance.FormatVersion, encoding == null ? Encoding.ASCII : encoding);
            }

            // Add it to the message list
            instance.Dialogs.Add(message);
        }

        return instance;
    }

    public static MessageScript FromBinary(MessageScriptBinaryV2 binary, FormatVersion version = FormatVersion.Detect, Encoding encoding = null)
    {
        if (binary == null)
            throw new ArgumentNullException(nameof(binary));

        // Create new script instance & set user id, format version
        var instance = new MessageScript
        {
            FormatVersion = version == FormatVersion.Detect ? (FormatVersion)binary.FormatVersion : version,
            Encoding = encoding
        };

        // Convert the binary messages to their counterpart
        var labelOccurences = new Dictionary<string, int>();
        foreach (var messageHeader in binary.Header2.DialogArray.Value)
        {
            IDialog message;
            IReadOnlyList<int> pageStartAddresses;
            IReadOnlyList<byte> buffer;
            int pageCount;

            switch (messageHeader.Value)
            {
                case BinaryMessageDialogV2 binaryMessage:
                    {
                        pageStartAddresses = binaryMessage.PageStartAddresses;
                        buffer = binaryMessage.TextBuffer;
                        pageCount = binaryMessage.PageCount;

                        // check for duplicates
                        var name = ResolveName(labelOccurences, binaryMessage.Name);

                        if (binaryMessage.SpeakerId == 0xFFFF)
                        {
                            message = new MessageDialog(name);
                        }
                        else if ((binaryMessage.SpeakerId & 0x8000) == 0x8000)
                        {
                            Trace.WriteLine(binaryMessage.SpeakerId.ToString("X4"));

                            message = new MessageDialog(name, new VariableSpeaker(binaryMessage.SpeakerId & 0x0FFF));
                        }
                        else
                        {
                            // TODO
                            message = new MessageDialog(name, new VariableSpeaker(binaryMessage.SpeakerId));

                            //if (binary.SpeakerTableHeader.SpeakerNameArray.Value == null)
                            //    throw new InvalidDataException("Speaker name array is null while being referenced");

                            //TokenText speakerName = null;
                            //if (binaryMessage.SpeakerId < binary.SpeakerTableHeader.SpeakerCount)
                            //{
                            //    speakerName = ParseSpeakerText(binary.SpeakerTableHeader.SpeakerNameArray
                            //        .Value[binaryMessage.SpeakerId].Value, instance.FormatVersion, encoding == null ? Encoding.ASCII : encoding);
                            //}

                            //message = new MessageDialog(name, new NamedSpeaker(speakerName));
                        }
                    }
                    break;

                case BinarySelectionDialogV2 binarySelection:
                    {
                        pageStartAddresses = binarySelection.OptionStartAddresses;
                        buffer = binarySelection.TextBuffer;
                        pageCount = binarySelection.OptionCount;
                        var name = ResolveName(labelOccurences, binarySelection.Name);
                        message = new SelectionDialog(name);
                    }
                    break;

                default:
                    throw new InvalidDataException("Unknown message type");
            }

            if (pageCount != 0)
            {
                // Parse the line data
                ParsePages(message, pageStartAddresses, buffer, instance.FormatVersion, encoding == null ? Encoding.ASCII : encoding);
            }

            // Add it to the message list
            instance.Dialogs.Add(message);
        }

        return instance;
    }

    /// <summary>
    /// Deserializes and creates a <see cref="MessageScript"/> from a file.
    /// </summary>
    public static MessageScript FromFile(string path, FormatVersion version = FormatVersion.Version1, Encoding encoding = null)
    {
        if (path == null)
            throw new ArgumentNullException(nameof(path));

        var binary = MessageScriptBinaryFactory.FromFile(path);
        return FromBinary(binary);
    }

    /// <summary>
    /// Deserializes and creates a <see cref="MessageScript"/> from a stream.
    /// </summary>
    public static MessageScript FromStream(Stream stream, FormatVersion version = FormatVersion.Version1, Encoding encoding = null, bool leaveOpen = false)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));


        var binary = MessageScriptBinaryFactory.FromStream(stream);
        return FromBinary(binary);
    }

    private static string ResolveName(Dictionary<string, int> labelOccurences, string name)
    {
        if (labelOccurences.ContainsKey(name))
        {
            labelOccurences[name] += 1;
            name = name + "_" + labelOccurences[name];
        }
        else
        {
            labelOccurences[name] = 1;
        }

        return name;
    }

    private static void ParsePages(IDialog message, IReadOnlyList<int> lineStartAddresses, IReadOnlyList<byte> buffer, FormatVersion version, Encoding encoding)
    {
        if (lineStartAddresses.Count == 0 || buffer.Count == 0)
            return;

        // The addresses are not relative to the start of the buffer
        // so we rebase the addresses first
        int lineStartAddressBase = lineStartAddresses[0];
        int[] rebasedLineStartAddresses = new int[lineStartAddresses.Count];

        for (int i = 0; i < lineStartAddresses.Count; i++)
            rebasedLineStartAddresses[i] = lineStartAddresses[i] - lineStartAddressBase;

        for (int lineIndex = 0; lineIndex < rebasedLineStartAddresses.Length; lineIndex++)
        {
            // Initialize a new line
            var line = new TokenText();

            // Now that the line start addresses have been rebased, we can use them as indices into the buffer
            int bufferIndex = rebasedLineStartAddresses[lineIndex];

            // Calculate the line end index
            int lineEndIndex = (lineIndex + 1) != rebasedLineStartAddresses.Length ? rebasedLineStartAddresses[lineIndex + 1] : buffer.Count;

            // Loop over the buffer until we find a 0 byte or have reached the end index
            while (bufferIndex < lineEndIndex)
            {
                if (!TryParseTokens(buffer, ref bufferIndex, out var tokens, version, encoding))
                    break;

                line.Tokens.AddRange(tokens);
            }

            // Add line to list of lines
            message.Lines.Add(line);
        }
    }

    private static TokenText ParseSpeakerText(IReadOnlyList<byte> bytes, FormatVersion version, Encoding encoding)
    {
        var line = new TokenText();

        int bufferIndex = 0;

        while (bufferIndex < bytes.Count)
        {
            if (!TryParseTokens(bytes, ref bufferIndex, out var tokens, version, encoding))
                break;

            line.Tokens.AddRange(tokens);
        }

        return line;
    }

    private static bool TryParseTokens(IReadOnlyList<byte> buffer, ref int bufferIndex, out List<IToken> tokens, FormatVersion version, Encoding encoding)
    {
        if (version.HasFlag(FormatVersion.Version2))
        {
            return TryParseTokensV2(buffer, ref bufferIndex, out tokens, version, encoding);
        }
        else
        {
            return TryParseTokensV1(buffer, ref bufferIndex, out tokens, version, encoding);
        }
    }

    private static bool TryReadUInt16(IReadOnlyList<byte> buffer, ref int bufferIndex, FormatVersion version, out ushort value)
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

    private static bool TryParseTokensV2(IReadOnlyList<byte> buffer, ref int bufferIndex, out List<IToken> tokens, FormatVersion version, Encoding encoding)
    {
        static bool IsUnicodeCharacter(ushort c)
        {
            return ((ushort)(c + 0x2800)) > 0x7FF;
        }
        static char MapToUnicodeCharacter(ushort c)
        {
            if (c == 0xFFE3)
            {
                return ' ';
            }
            else
            {
                return (char)c;
            }
        }
        static bool IsSafeCharacter(ushort c)
        {
            return (c >= 21 && c <= 126) || (c == 0xFFE3);
        }

        tokens = [];

        if (!TryReadUInt16(buffer, ref bufferIndex, version, out var c))
            return false;
        if (c == 0)
            return false;

        if (IsUnicodeCharacter(c))
        {
            if (!IsSafeCharacter(c))
            {
                tokens.Add(new CodePointToken((byte)((c & 0xFF00) >> 8), (byte)(c & 0xFF)));
            }
            else
            {
                var stringBuilder = new StringBuilder();
                stringBuilder.Append(MapToUnicodeCharacter(c));
                while (true)
                {
                    if (!TryReadUInt16(buffer, ref bufferIndex, version, out c))
                        break;
                    if (!(IsUnicodeCharacter(c) && IsSafeCharacter(c)))
                    {
                        bufferIndex -= 2;
                        break;
                    }
                    stringBuilder.Append(MapToUnicodeCharacter(c));
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
                    if (!TryReadUInt16(buffer, ref bufferIndex, version, out var temp))
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
                    if (!TryReadUInt16(buffer, ref bufferIndex, version, out var temp))
                        break;
                    args.Add(temp);
                }
            }

            tokens.Add(new FunctionToken(0, c, args, false));
        }

        return true;
    }

    private static bool TryParseTokensV1(IReadOnlyList<byte> buffer, ref int bufferIndex, out List<IToken> tokens, FormatVersion version, Encoding encoding)
    {
        byte b = buffer[bufferIndex++];
        tokens = new List<IToken>();

        // Check if the current byte signifies a function
        if (b == 0)
        {
            tokens = null;
            return false;
        }
        if (b == NewLineToken.Value)
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

            if (b == 0 || b == NewLineToken.Value || (b & 0xF0) == 0xF0)
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

    /// <summary>
    /// Gets or sets the user id. Serves as metadata.
    /// </summary>
    public short Id { get; set; }

    /// <summary>
    /// Gets or sets the format version this script will use in its binary form.
    /// </summary>
    public FormatVersion FormatVersion { get; set; }

    /// <summary>
    /// Gets or sets the encoding used for the text.
    /// </summary>
    public Encoding Encoding { get; set; }

    /// <summary>
    /// Gets the list of <see cref="IDialog"/> in this script.
    /// </summary>
    public List<IDialog> Dialogs { get; }

    /// <summary>
    /// Creates a new instance of <see cref="MessageScript"/> initialized with default values.
    /// </summary>
    private MessageScript()
    {
        Id = 0;
        FormatVersion = FormatVersion.Version1;
        Encoding = null;
        Dialogs = new List<IDialog>();
    }

    /// <summary>
    /// Creates a new instance of <see cref="MessageScript"/> initialized with default values.
    /// </summary>
    public MessageScript(FormatVersion version, Encoding encoding = null)
    {
        Id = 0;
        FormatVersion = version;
        Encoding = encoding;
        Dialogs = new List<IDialog>();
    }

    /// <summary>
    /// Converts this <see cref="MessageScript"/> instance to a <see cref="MessageScriptBinary"/> instance.
    /// </summary>
    /// <returns></returns>
    public MessageScriptBinary ToBinary()
    {
        var builder = new MessageScriptBinaryBuilder((BinaryFormatVersion)FormatVersion);

        builder.SetUserId(Id);
        builder.SetEncoding(Encoding);

        foreach (var dialog in Dialogs)
        {
            switch (dialog.Kind)
            {
                case DialogKind.Message:
                    builder.AddDialog((MessageDialog)dialog);
                    break;
                case DialogKind.Selection:
                    builder.AddDialog((SelectionDialog)dialog);
                    break;

                default:
                    throw new NotImplementedException(dialog.Kind.ToString());
            }
        }

        return builder.Build();
    }

    /// <summary>
    /// Serializes and writes this <see cref="MessageScript"/> instance to the specified file.
    /// </summary>
    /// <param name="path"></param>
    public void ToFile(string path)
    {
        if (path == null)
            throw new ArgumentNullException(nameof(path));

        if (string.IsNullOrEmpty(path))
            throw new ArgumentException("Value cannot be null or empty.", nameof(path));

        using (var stream = FileUtils.Create(path))
            ToStream(stream);
    }

    /// <summary>
    /// Serializes and writes this <see cref="MessageScript"/> instance to a stream.
    /// </summary>
    /// <returns></returns>
    public Stream ToStream()
    {
        var stream = new MemoryStream();
        ToStream(stream, true);
        return stream;
    }

    /// <summary>
    /// Serializes and writes this <see cref="MessageScript"/> instance to the specified stream.
    /// </summary>
    /// <param name="stream">The stream to write to.</param>
    /// <param name="leaveOpen">Whether to stream should be left open or not.</param>
    public void ToStream(Stream stream, bool leaveOpen = false)
    {
        var binary = ToBinary();
        binary.ToStream(stream, leaveOpen);
    }
}
