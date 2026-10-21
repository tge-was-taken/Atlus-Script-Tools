using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.Common.Text.Encodings;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V1;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V3;
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
        else if (binary is Bm2Binary v3)
            return FromBinary(v3, version, encoding);
        else
            throw new NotSupportedException();
    }

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
            Version0 = binary.Header.Magic != null &&
                       binary.Header.Magic.SequenceEqual(BinaryModel.V1.BinaryHeader.MAGIC_V0),
        };
        instance.Encoding = EncodingHelper.GetEncodingForEndianness(encoding, version.HasFlag(FormatVersion.BigEndian)) ?? Encoding.ASCII;

        // Convert the binary messages to their counterpart
        var labelOccurences = new Dictionary<string, int>();
        var seenOffsets = new HashSet<int>();
        foreach (var messageHeader in binary.DialogHeaders)
        {
            IDialog message;
            IReadOnlyList<int> pageStartAddresses;
            IReadOnlyList<byte> buffer;
            int pageCount;

            // A table entry sharing its data offset with an earlier one is a dialog that repeats that dialog's
            // name, so keep the name as is instead of making it unique.
            var isRepeatedName = messageHeader.Data.Offset != 0 && !seenOffsets.Add(messageHeader.Data.Offset);

            switch (messageHeader.Kind)
            {
                case BinaryDialogKind.Message:
                    {
                        var binaryMessage = (BinaryMessageDialog)messageHeader.Data.Value;
                        pageStartAddresses = binaryMessage.PageStartAddresses;
                        buffer = binaryMessage.TextBuffer;
                        pageCount = binaryMessage.PageCount;

                        // check for duplicates
                        var name = isRepeatedName ? binaryMessage.Name : ResolveName(labelOccurences, binaryMessage.Name);

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
                                    .Value[binaryMessage.SpeakerId].Value, instance.FormatVersion, instance.Encoding);
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
                        var name = isRepeatedName ? binaryMessage.Name : ResolveName(labelOccurences, binaryMessage.Name);
                        message = new SelectionDialog(name, (SelectionDialogPattern)binaryMessage.Pattern)
                        {
                            OmitTrailingTerminator = !HasTrailingTerminator(pageStartAddresses, buffer)
                        };
                    }
                    break;

                default:
                    throw new InvalidDataException("Unknown message type");
            }

            if (pageCount != 0)
            {
                // Parse the line data
                var endedOnTerminator = ParsePages(message, pageStartAddresses, buffer, instance.FormatVersion, instance.Encoding);

                if (message is MessageDialog messageDialog)
                    messageDialog.OmitTrailingTerminator = !endedOnTerminator;
            }

            // Add it to the message list
            instance.Dialogs.Add(message);
        }

        return instance;
    }


    /// <summary>
    /// Creates a <see cref="MessageScript"/> from a <see cref="MessageScriptBinaryV2"/>.
    /// </summary>
    public static MessageScript FromBinary(MessageScriptBinaryV2 binary, FormatVersion version = FormatVersion.Detect, Encoding encoding = null)
    {
        if (binary == null)
            throw new ArgumentNullException(nameof(binary));


        // Create new script instance & set user id, format version
        var instance = new MessageScript
        {
            FormatVersion = version == FormatVersion.Detect ? (FormatVersion)binary.FormatVersion : version,
        };
        var isBigEndian = instance.FormatVersion.HasFlag(FormatVersion.BigEndian);
        instance.Encoding =
            EncodingHelper.GetEncodingForEndianness(encoding, isBigEndian)
            ?? EncodingHelper.GetEncodingForEndianness(Encoding.Unicode, isBigEndian);

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
                        else
                        {
                            message = new MessageDialog(name, new VariableSpeaker(binaryMessage.SpeakerId));
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
                ParsePages(message, pageStartAddresses, buffer, instance.FormatVersion, instance.Encoding);
            }

            // Add it to the message list
            instance.Dialogs.Add(message);
        }

        return instance;
    }

    /// <summary>
    /// Creates a <see cref="MessageScript"/> from a <see cref="MessageScriptBinaryV2"/>.
    /// </summary>
    public static MessageScript FromBinary(Bm2Binary binary, FormatVersion version = FormatVersion.Detect, Encoding encoding = null)
    {
        if (binary == null)
            throw new ArgumentNullException(nameof(binary));

        // Create new script instance & set user id, format version
        var instance = new MessageScript
        {
            FormatVersion = version == FormatVersion.Detect ? (FormatVersion)binary.FormatVersion : version,
        };
        instance.Encoding = EncodingHelper.GetEncodingForEndianness(encoding, version.HasFlag(FormatVersion.BigEndian)) ?? Encoding.ASCII;

        // Convert the binary messages to their counterpart
        var labelOccurences = new Dictionary<string, int>();
        foreach (var messageHeader in binary.Messages)
        {
            IDialog message;
            IReadOnlyList<int> pageStartAddresses;
            IReadOnlyList<byte> buffer;
            uint pageCount;

            var binaryMessage = messageHeader;
            pageStartAddresses = binaryMessage.Data.PageOffsets;
            buffer = binaryMessage.Data.TextBuffer;
            pageCount = binaryMessage.Data.PageCount;

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
                if (binary.Speakers.Count == 0)
                    throw new InvalidDataException("Speaker name array is null while being referenced");

                TokenText speakerName = null;
                if (binaryMessage.SpeakerId < binary.Speakers.Count)
                {
                    speakerName = ParseSpeakerText(binary.Speakers[binaryMessage.SpeakerId].Data,
                        instance.FormatVersion, instance.Encoding);
                }

                message = new MessageDialog(name, new NamedSpeaker(speakerName));
            }

            if (pageCount != 0)
            {
                // Parse the line data
                ParsePages(message, pageStartAddresses, buffer, instance.FormatVersion, instance.Encoding);
            }

            // Add it to the message list
            instance.Dialogs.Add(message);
        }

        return instance;
    }

    /// <summary>
    /// Deserializes and creates a <see cref="MessageScript"/> from a file.
    /// </summary>
    public static MessageScript FromFile(string path, FormatVersion version = FormatVersion.Detect, Encoding encoding = null)
    {
        if (path == null)
            throw new ArgumentNullException(nameof(path));

        var binary = MessageScriptBinaryFactory.FromFile(path);
        return FromBinary(binary, version, encoding);
    }

    /// <summary>
    /// Deserializes and creates a <see cref="MessageScript"/> from a stream.
    /// </summary>
    public static MessageScript FromStream(Stream stream, FormatVersion version = FormatVersion.Detect, Encoding encoding = null, bool leaveOpen = false)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));


        var binary = MessageScriptBinaryFactory.FromStream(stream);
        return FromBinary(binary, version, encoding);
    }

    internal static string ResolveName(Dictionary<string, int> labelOccurences, string name)
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

    // Each option ends with a terminator and one more normally follows the last of them, so two
    // terminators after the last option's text mean the trailing one is there.
    private static bool HasTrailingTerminator(IReadOnlyList<int> optionStartAddresses, IReadOnlyList<byte> buffer)
    {
        if (optionStartAddresses.Count == 0 || buffer.Count == 0)
            return true;

        var index = optionStartAddresses[optionStartAddresses.Count - 1] - optionStartAddresses[0];
        while (index < buffer.Count && buffer[index] != 0)
            index++;

        return index + 1 < buffer.Count;
    }

    /// <summary>
    /// Parses the pages out of a text buffer. Returns whether the last page ended on a terminator
    /// instead of running up to the end of the buffer.
    /// </summary>
    private static bool ParsePages(IDialog message, IReadOnlyList<int> lineStartAddresses, IReadOnlyList<byte> buffer, FormatVersion version, Encoding encoding)
    {
        if (lineStartAddresses.Count == 0 || buffer.Count == 0)
            return true;

        bool endedOnTerminator = false;

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

            // An unreferenced copy of a dialog keeps the page addresses of the dialog it copies, which
            // can point past its own shorter text, so read what is there and leave the rest empty.
            bufferIndex = Math.Min(bufferIndex, buffer.Count);
            lineEndIndex = Math.Min(lineEndIndex, buffer.Count);

            endedOnTerminator = false;

            // Loop over the buffer until we find a 0 byte or have reached the end index
            while (bufferIndex < lineEndIndex)
            {
                // A token that runs past the end of the buffer ends the page: the bytes it would read
                // are not there, which happens in the copies described above.
                List<IToken> tokens;
                try
                {
                    if (!TryParseTokens(buffer, ref bufferIndex, out tokens, version, encoding))
                    {
                        endedOnTerminator = true;
                        break;
                    }
                }
                catch (Exception exception) when (exception is IndexOutOfRangeException ||
                                                  exception is ArgumentOutOfRangeException)
                {
                    break;
                }

                line.Tokens.AddRange(tokens);
            }

            // Add line to list of lines
            message.Lines.Add(line);
        }

        return endedOnTerminator;
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
            return MessageScriptBinaryV2TokenParser.TryParseTokens(buffer, ref bufferIndex, out tokens, version, encoding);
        }
        else if (version.HasFlag(FormatVersion.Version3))
        {
            return Bm2BinaryTokenParser.TryParseTokens(buffer, ref bufferIndex, out tokens, version, encoding);
        }
        else
        {
            return MessageScriptBinaryTokenParser.TryParseTokens(buffer, ref bufferIndex, out tokens, version, encoding);
        }
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
    /// Write the older MSG0 layout: its magic and an 8 byte speaker table header.
    /// </summary>
    public bool Version0 { get; set; }

    /// <summary>
    /// End a selection dialog's text buffer after the last option's terminator instead of adding
    /// another one.
    /// </summary>

    /// <summary>
    /// Creates a new instance of <see cref="MessageScript"/> initialized with default values.
    /// </summary>
    public MessageScript()
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
    /// Gets a unique identifier per dialog, for referring to dialogs by name. Dialogs may share a name,
    /// so repeats get a numeric suffix.
    /// </summary>
    public List<string> GetDialogIdentifiers()
    {
        var occurences = new Dictionary<string, int>();
        var identifiers = new List<string>(Dialogs.Count);

        foreach (var dialog in Dialogs)
            identifiers.Add(ResolveName(occurences, dialog.Name));

        return identifiers;
    }

    /// <summary>
    /// Converts this <see cref="MessageScript"/> instance to a <see cref="MessageScriptBinary"/> instance.
    /// </summary>
    /// <returns></returns>
    public IMessageScriptBinary ToBinary()
    {
        if (FormatVersion.HasFlag(FormatVersion.Version2))
            return ToBinaryV2();
        else if (FormatVersion.HasFlag(FormatVersion.Version3))
            return ToBinaryV3();
        else
            return ToBinaryV1();
    }

    private MessageScriptBinary ToBinaryV1()
    {
        var builder = new MessageScriptBinaryBuilder((BinaryFormatVersion)FormatVersion);

        builder.SetUserId(Id);
        builder.SetVersion0(Version0);

        if (Encoding != null)
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

    private MessageScriptBinaryV2 ToBinaryV2()
    {
        var builder = new MessageScriptBinaryV2Builder((BinaryFormatVersion)FormatVersion);

        if (Encoding != null)
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

    private Bm2Binary ToBinaryV3()
    {
        var builder = new Bm2BinaryBuilder((BinaryFormatVersion)FormatVersion);

        if (Encoding != null)
            builder.SetEncoding(Encoding);

        foreach (var dialog in Dialogs)
        {
            switch (dialog.Kind)
            {
                case DialogKind.Message:
                    builder.AddDialog((MessageDialog)dialog);
                    break;
                //case DialogKind.Selection:
                //    //builder.AddDialog((SelectionDialog)dialog);
                //    break;

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
