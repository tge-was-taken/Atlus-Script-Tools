using AtlusScriptLibrary.Common.Collections;
using AtlusScriptLibrary.Common.Text.Encodings;
using MoreLinq;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V3;

public class Bm2BinaryBuilder
{
    private Encoding mEncoding;
    private readonly List<Bm2Speaker> mSpeakers;
    private readonly List<Bm2Message> mMessages;
    private int mPosition;
    private BinaryFormatVersion mFormatVersion;


    public Bm2BinaryBuilder(BinaryFormatVersion formatVersion)
    {
        mEncoding = EncodingHelper.GetEncodingForEndianness(Encoding.ASCII, mFormatVersion.HasFlag(BinaryFormatVersion.BigEndian));
        mSpeakers = new();
        mMessages = new();
        mPosition = 0;
        mFormatVersion = formatVersion;
    }

    public void SetEncoding(Encoding encoding)
    {
        if (encoding == null) throw new ArgumentNullException(nameof(encoding));
        mEncoding = EncodingHelper.GetEncodingForEndianness(encoding, mFormatVersion.HasFlag(BinaryFormatVersion.BigEndian));
    }

    public void AddDialog(MessageDialog message)
    {
        var bm2Message = new Bm2Message
        {
            Name = message.Name.Substring(0, Math.Min(message.Name.Length, 32)), // Truncate to max 32 characters
            SpeakerId = GetSpeakerId(message.Speaker),
            Data = BuildMessageData(message)
        };

        bm2Message.DataSize = (uint)(4 + bm2Message.Data.PageOffsets.Count * 4 + bm2Message.Data.TextBuffer.Length);
        mMessages.Add(bm2Message);
    }

    public Bm2Binary Build()
    {
        var binary = new Bm2Binary
        {
            Header = new Bm2Header
            {
                Magic = mFormatVersion.HasFlag(BinaryFormatVersion.BigEndian) ? Bm2Header.MAGIC_BE : Bm2Header.MAGIC,
                Version = Bm2Header.VERSION,
                Header2Offset = 0x20,
            },
            Header2 = new Bm2Header2
            {
                SpeakerCount = (uint)mSpeakers.Count,
                MessageCount = (uint)mMessages.Count
            },
            Speakers = mSpeakers,
            Messages = mMessages,
            FormatVersion = mFormatVersion
        };

        var currentOffset = 0x30u; 
        binary.Header2.SpeakerArrayOffset = currentOffset;
        currentOffset += (uint)(binary.Speakers.Count * 0x10);
        foreach (var speaker in binary.Speakers)
        {
            speaker.DataOffset = currentOffset;
            currentOffset += speaker.DataSize;
        }

        binary.Header2.MessageArrayOffset = currentOffset;
        currentOffset += (uint)(binary.Messages.Count * 0x40);
        foreach (var message in binary.Messages)
        {
            message.DataOffset = (uint)currentOffset;
            currentOffset += (uint)message.DataSize;
        }

        binary.Header.FileSize = (uint)currentOffset;
        return binary;
    }

    private Bm2MessageData BuildMessageData(MessageDialog message)
    {
        var data = new Bm2MessageData
        {
            PageCount = (uint)message.Pages.Count,
            PageOffsets = new List<int>(),
            TextBuffer = new byte[0]
        };

        var textBuffer = new List<byte>();
        var currentPageOffset = 4 + message.Pages.Count * 4;

        foreach (var page in message.Pages)
        {
            data.PageOffsets.Add(currentPageOffset);
            var pageBytes = ProcessPage(page);
            textBuffer.AddRange(pageBytes);
            currentPageOffset += pageBytes.Count;
        }

        data.TextBuffer = textBuffer.ToArray();
        return data;
    }

    private List<byte> ProcessPage(TokenText page)
    {
        var bytes = new List<byte>();
        foreach (var token in page.Tokens)
        {
            switch (token)
            {
                case StringToken strToken:
                    // Encode plain text
                    bytes.AddRange(mEncoding.GetBytes(strToken.Value));
                    break;

                case CodePointToken codePoint:
                    if (codePoint.Bytes.Count == 2)
                    {
                        WriteUInt16(bytes, (ushort)(codePoint.Bytes[0] << 8 | codePoint.Bytes[1]));
                    }
                    else
                    {
                        foreach (var item in codePoint.Bytes)
                            WriteByte(bytes, item);
                    }
                    break;

                case FunctionToken funcToken:
                    WriteByte(bytes, 0xFF);
                    WriteUInt16(bytes, (ushort)funcToken.FunctionIndex);
                    WriteUInt16(bytes, (ushort)funcToken.Arguments[0]);
                    foreach (var arg in funcToken.Arguments.Skip(1))
                        WriteByte(bytes, (byte)(arg & 0xFF));
                    break;

                case NewLineToken _:
                    WriteByte(bytes, 0);
                    break;

                default:
                    throw new NotImplementedException($"Unsupported token kind: {token.Kind}");
            }
        }

        return bytes;
    }

    private ushort GetSpeakerId(ISpeaker speaker)
    {
        if (speaker == null) return 0xFFFF; // No speaker

        switch (speaker)
        {
            case NamedSpeaker namedSpeaker:
                var data = ProcessPage(namedSpeaker.Name);
                var index = mSpeakers.FindIndex(x => x.Data.SequenceEqual(data));
                if (index == -1)
                {
                    index = mSpeakers.Count;
                    mSpeakers.Add(new Bm2Speaker()
                    {
                        Data = data.ToArray(),
                        DataSize = (uint)data.Count,
                    });
                }
                return (ushort)index;

            case VariableSpeaker variableSpeaker:
                return (ushort)variableSpeaker.Index;

            default:
                throw new ArgumentException($"Unsupported speaker type: {speaker.GetType()}");
        }
    }

    private void WriteByte(List<byte> bytes, byte value)
        => bytes.Add(value);

    private void WriteUInt16(List<byte> bytes, ushort value)
    {
        Span<byte> temp = stackalloc byte[2];
        if (mFormatVersion.HasFlag(BinaryFormatVersion.BigEndian))
            BinaryPrimitives.WriteUInt16BigEndian(temp, value);
        else
            BinaryPrimitives.WriteUInt16LittleEndian(temp, value);
        bytes.Add(temp[0]);
        bytes.Add(temp[1]);
    }
}