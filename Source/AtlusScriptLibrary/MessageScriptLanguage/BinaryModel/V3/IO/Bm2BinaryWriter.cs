using AtlusScriptLibrary.Common.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V3.IO;

public sealed class Bm2BinaryWriter : IDisposable
{
    private bool _disposed;
    private readonly long _positionBase;
    private readonly EndianBinaryWriter _writer;

    public Bm2BinaryWriter(Stream stream, BinaryFormatVersion version, bool leaveOpen = false)
    {
        _positionBase = stream.Position;
        _writer = new EndianBinaryWriter(
            stream,
            Encoding.ASCII,
            leaveOpen,
            version.HasFlag(BinaryFormatVersion.BigEndian) ? Endianness.BigEndian : Endianness.LittleEndian);
    }

    public void Dispose()
    {
        if (_disposed) return;

        _writer.Dispose();
        _disposed = true;
    }

    public void WriteBinary(Bm2Binary binary)
    {
        WriteHeader(binary.Header);

        if (binary.Header.Header2Offset != 0)
        {
            SeekToOffset(binary.Header.Header2Offset);
            WriteHeader2(binary.Header2);

            if (binary.Header2.SpeakerArrayOffset != 0 && binary.Speakers != null)
            {
                SeekToOffset(binary.Header2.SpeakerArrayOffset);
                WriteSpeakers(binary.Speakers);
            }

            if (binary.Header2.MessageArrayOffset != 0 && binary.Messages != null)
            {
                SeekToOffset(binary.Header2.MessageArrayOffset);
                WriteMessages(binary.Messages);
            }
        }
    }

    private void WriteHeader(Bm2Header header)
    {
        _writer.Write(header.Field00);
        _writer.Write(header.Magic);
        _writer.Write(header.Version);
        _writer.Write(header.FileSize);
        _writer.Write(header.Header2Offset);
    }

    private void WriteHeader2(Bm2Header2 header2)
    {
        _writer.Write(header2.SpeakerCount);
        _writer.Write(header2.SpeakerArrayOffset);
        _writer.Write(header2.MessageCount);
        _writer.Write(header2.MessageArrayOffset);
    }

    private void WriteSpeakers(IList<Bm2Speaker> speakers)
    {
        foreach (var speaker in speakers)
        {
            _writer.Write(speaker.Field00);
            _writer.Write(speaker.DataSize);
            _writer.Write(speaker.DataOffset);
            _writer.Write(speaker.Field0C);

            if (speaker.Data != null && speaker.DataOffset != 0)
            {
                long currentPos = _writer.BaseStream.Position;
                SeekToOffset(speaker.DataOffset);
                _writer.Write(speaker.Data);
                _writer.BaseStream.Position = currentPos;
            }
        }
    }

    private void WriteMessages(IList<Bm2Message> messages)
    {
        foreach (var message in messages)
        {
            _writer.Write(
                message.Name.PadRight(32, '\0')
                    .Substring(0, 32)
                    .ToCharArray());
            _writer.Write(message.Field30);
            _writer.Write(message.DataSize);
            _writer.Write(message.DataOffset);
            _writer.Write(message.SpeakerId);
            _writer.Write(message.Field3E);
            _writer.Write(message.Field40);
            _writer.Write(message.Field44);
            _writer.Write(message.Field48);
            _writer.Write(message.Field4C);

            if (message.Data != null && message.DataOffset != 0)
            {
                long currentPos = _writer.BaseStream.Position;
                SeekToOffset(message.DataOffset);
                WriteMessageData(message.Data);
                _writer.BaseStream.Position = currentPos;
            }
        }
    }

    private void WriteMessageData(Bm2MessageData data)
    {
        _writer.Write(data.PageCount);

        foreach (var offset in data.PageOffsets)
        {
            _writer.Write(offset);
        }

        _writer.Write(data.TextBuffer);
    }

    private void SeekToOffset(uint offset)
    {
        _writer.SeekBegin(_positionBase + offset);
    }
}
