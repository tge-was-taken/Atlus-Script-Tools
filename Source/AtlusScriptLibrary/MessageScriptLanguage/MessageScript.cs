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
using System.Linq;
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
            Relocated = binary.Header.IsRelocated,
        };
        instance.Encoding = EncodingHelper.GetEncodingForEndianness(encoding, version.HasFlag(FormatVersion.BigEndian)) ?? Encoding.ASCII;

        // Convert the binary messages to their counterpart
        var labelOccurences = new Dictionary<string, int>();
        var nameByOffset = new Dictionary<int, string>();

        // A speaker table entry that more than one dialog points at was shared, which the builder
        // only does on its own for a plain text name.
        var sharedSpeakerIds = binary.DialogHeaders
            .Select(x => x.Data.Value as BinaryMessageDialog?)
            .Where(x => x.HasValue)
            .GroupBy(x => x.Value.SpeakerId)
            .Where(x => x.Count() > 1)
            .Select(x => x.Key)
            .ToHashSet();
        var sharesByDefault = instance.FormatVersion.HasFlag(FormatVersion.Version1) &&
                              !instance.FormatVersion.HasFlag(FormatVersion.BigEndian);
        foreach (var messageHeader in binary.DialogHeaders)
        {
            IDialog message;
            IReadOnlyList<int> pageStartAddresses;
            IReadOnlyList<byte> buffer;
            int pageCount;
            int bufferAddress;

            // A table entry sharing its data offset with an earlier one is a dialog repeating that
            // dialog's name, so it takes the name already resolved for it. Several dialogs can share
            // a trimmed name, so the raw name alone does not say which one that is.
            string DialogName(string rawName)
            {
                var offset = messageHeader.Data.Offset;
                if (offset != 0 && nameByOffset.TryGetValue(offset, out var shared))
                    return shared;

                var resolved = ResolveName(labelOccurences, rawName);
                if (offset != 0)
                    nameByOffset[offset] = resolved;

                return resolved;
            }

            switch (messageHeader.Kind)
            {
                case BinaryDialogKind.Message:
                    {
                        var binaryMessage = (BinaryMessageDialog)messageHeader.Data.Value;
                        pageStartAddresses = binaryMessage.PageStartAddresses;
                        buffer = binaryMessage.TextBuffer;
                        pageCount = binaryMessage.PageCount;
                        bufferAddress = messageHeader.DataLocation + 0x1C
                            + ((pageCount + 1) * sizeof(int));

                        // check for duplicates
                        var name = DialogName(binaryMessage.Name);

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

                            message = new MessageDialog(name, new NamedSpeaker(speakerName))
                            {
                                ShareSpeakerName = !sharesByDefault &&
                                                   sharedSpeakerIds.Contains(binaryMessage.SpeakerId) &&
                                                   speakerName != null &&
                                                   speakerName.Tokens.Any(x => x.Kind == TokenKind.Function)
                            };
                        }
                    }
                    break;

                case BinaryDialogKind.Selection:
                    {
                        var binaryMessage = (BinarySelectionDialog)messageHeader.Data.Value;
                        pageStartAddresses = binaryMessage.OptionStartAddresses;
                        buffer = binaryMessage.TextBuffer;
                        pageCount = binaryMessage.OptionCount;
                        bufferAddress = messageHeader.DataLocation + 0x20
                            + ((pageCount + 1) * sizeof(int));
                        var name = DialogName(binaryMessage.Name);
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
                var endedOnTerminator = ParsePages(message, pageStartAddresses, buffer, instance.FormatVersion, instance.Encoding, bufferAddress);

                if (message is MessageDialog messageDialog)
                    messageDialog.OmitTrailingTerminator = !endedOnTerminator;
            }

            // Add it to the message list
            instance.Dialogs.Add(message);
        }

        var usedSpeakerIds = binary.DialogHeaders
            .Select(x => x.Data.Value as BinaryMessageDialog?)
            .Where(x => x.HasValue)
            .Select(x => (int)x.Value.SpeakerId)
            .ToHashSet();
        var speakerNames = binary.SpeakerTableHeader.SpeakerNameArray.Value;
        for (int i = 0; speakerNames != null && i < binary.SpeakerTableHeader.SpeakerCount; i++)
        {
            if (!usedSpeakerIds.Contains(i))
                instance.UnusedSpeakerNames.Add((i, speakerNames[i].Value?.ToArray() ?? Array.Empty<byte>()));
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
        if (!labelOccurences.TryGetValue(name, out var count))
        {
            labelOccurences[name] = 1;
            return name;
        }

        // A suffixed name can be a name in its own right, so keep counting until it is free.
        string resolved;
        do
        {
            count++;
            resolved = name + "_" + count;
        }
        while (labelOccurences.ContainsKey(resolved));

        labelOccurences[name] = count;
        labelOccurences[resolved] = 1;
        return resolved;
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
    private static bool ParsePages(IDialog message, IReadOnlyList<int> lineStartAddresses, IReadOnlyList<byte> buffer, FormatVersion version, Encoding encoding, int bufferAddress = -1)
    {
        if (lineStartAddresses.Count == 0 || buffer.Count == 0)
            return true;

        bool endedOnTerminator = false;

        // The addresses are not relative to the start of the buffer
        // so we rebase the addresses first
        int lineStartAddressBase = lineStartAddresses[0];
        int[] rebasedLineStartAddresses = new int[lineStartAddresses.Count];

        bool[] inherited = new bool[lineStartAddresses.Count];

        for (int i = 0; i < lineStartAddresses.Count; i++)
        {
            // An address that lands inside this buffer is this dialog's own. One that does not was
            // inherited from the dialog whose name this one repeats, so fall back to the first address,
            // which puts the pages in plausible places without claiming to know the real split.
            var own = lineStartAddresses[i] - bufferAddress;
            inherited[i] = !(bufferAddress >= 0 && own >= 0 && own <= buffer.Count);
            rebasedLineStartAddresses[i] = inherited[i]
                ? lineStartAddresses[i] - lineStartAddressBase
                : own;
        }

        // A page start the previous page had to give back, because the token there crosses the boundary.
        int carriedStart = -1;

        for (int lineIndex = 0; lineIndex < rebasedLineStartAddresses.Length; lineIndex++)
        {
            // Initialize a new line
            var line = new TokenText();

            // Now that the line start addresses have been rebased, we can use them as indices into the buffer
            int bufferIndex = carriedStart >= 0 ? carriedStart : rebasedLineStartAddresses[lineIndex];
            carriedStart = -1;

            // Calculate the line end index
            int lineEndIndex = (lineIndex + 1) != rebasedLineStartAddresses.Length ? rebasedLineStartAddresses[lineIndex + 1] : buffer.Count;

            // An unreferenced copy of a dialog keeps the page addresses of the dialog it copies, which
            // can point past its own shorter text, so read what is there and leave the rest empty.
            bufferIndex = Math.Min(bufferIndex, buffer.Count);
            lineEndIndex = Math.Min(lineEndIndex, buffer.Count);

            // A copy's borrowed addresses can leave a trailing page with no bytes of its own, which
            // says nothing about how the text ended, so keep what the last page with bytes found.
            if (bufferIndex < lineEndIndex)
                endedOnTerminator = false;

            // A run of text stops at the end of the buffer it is given, so hand the parser a view that
            // ends where this page does. Without it a text run crosses into the next page and is read twice.
            var pageBuffer = lineEndIndex == buffer.Count ? buffer : new BufferView(buffer, lineEndIndex);

            // Loop over the buffer until we find a 0 byte or have reached the end index
            while (bufferIndex < lineEndIndex)
            {
                // A token that runs past the end of the buffer ends the page: the bytes it would read
                // are not there, which happens in the copies described above.
                List<IToken> tokens;
                int tokenIndex = bufferIndex;
                try
                {
                    if (!TryParseTokens(pageBuffer, ref bufferIndex, out tokens, version, encoding))
                    {
                        endedOnTerminator = true;

                        // A selection's options are terminator delimited, so a borrowed address for the
                        // next one says nothing: it starts right after this terminator.
                        if (lineIndex + 1 < inherited.Length && inherited[lineIndex + 1])
                            carriedStart = bufferIndex;

                        break;
                    }
                }
                catch (Exception exception) when (exception is IndexOutOfRangeException ||
                                                  exception is ArgumentOutOfRangeException)
                {
                    // Text splits anywhere, but a function token does not, so leave one that crosses
                    // the boundary to the next page. Only a copy's borrowed addresses land mid token.
                    if (lineEndIndex != buffer.Count)
                        carriedStart = tokenIndex;

                    break;
                }

                line.Tokens.AddRange(tokens);
            }

            // Add line to list of lines
            message.Lines.Add(line);
        }

        return endedOnTerminator;
    }

    /// <summary>
    /// A read only view of the first bytes of a buffer.
    /// </summary>
    private sealed class BufferView : IReadOnlyList<byte>
    {
        private readonly IReadOnlyList<byte> mBuffer;

        public BufferView(IReadOnlyList<byte> buffer, int count)
        {
            mBuffer = buffer;
            Count = count;
        }

        public int Count { get; }

        public byte this[int index] => index < Count ? mBuffer[index] : throw new IndexOutOfRangeException();

        public IEnumerator<byte> GetEnumerator()
        {
            for (int i = 0; i < Count; i++)
                yield return mBuffer[i];
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
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
    /// Name of the pragma that carries <see cref="Relocated"/> through the text format.
    /// </summary>
    public const string RelocatedPragma = "relocated";

    /// <summary>
    /// Prefix of the pragma that carries one <see cref="UnusedSpeakerNames"/> entry through the text
    /// format, as unusedspeaker_&lt;index&gt;_&lt;hex of the encoded name&gt;.
    /// </summary>
    public const string UnusedSpeakerPragmaPrefix = "unusedspeaker_";

    /// <summary>
    /// Speaker table entries that no dialog refers to, with the index they sit at. Nothing in the
    /// text implies them, so they are carried by a pragma.
    /// </summary>
    public List<(int Index, byte[] Name)> UnusedSpeakerNames { get; } = new();

    /// <summary>
    /// The original file was relocated: it is little endian, stores every pointer relative to the
    /// position of the pointer itself and keeps each text buffer size big endian.
    /// </summary>
    public bool Relocated { get; set; }

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
        builder.SetRelocated(Relocated);

        if (Encoding != null)
            builder.SetEncoding(Encoding);

        foreach (var (index, name) in UnusedSpeakerNames)
            builder.AddUnusedSpeakerName(index, name);

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
