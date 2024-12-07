using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.Common.Text.Encodings;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V3.IO;

public sealed class Bm2BinaryReader : IDisposable
{
    private readonly EndianBinaryReader _reader;
    private readonly long _positionBase;
    private BinaryFormatVersion _version;
    private bool _disposed;

    public Bm2BinaryReader(Stream stream, BinaryFormatVersion version, bool leaveOpen = false)
    {
        _positionBase = stream.Position;
        _reader = new EndianBinaryReader(stream, ShiftJISEncoding.Instance, version.HasFlag(BinaryFormatVersion.BigEndian) ? Endianness.BigEndian : Endianness.LittleEndian);
        _version = version;
    }

    private uint ReadUInt() => _reader.ReadUInt32();
    private ushort ReadUShort() => _reader.ReadUInt16();

    public Bm2Binary ReadBinary()
    {
        var file = new Bm2Binary
        {
            Header = ReadHeader()
        };

        if (file.Header.Header2Offset != 0)
        {
            _reader.BaseStream.Seek(_positionBase + file.Header.Header2Offset, SeekOrigin.Begin);
            file.Header2 = ReadHeader2();

            if (file.Header2.SpeakerArrayOffset != 0 && file.Header2.SpeakerCount > 0)
            {
                _reader.BaseStream.Seek(_positionBase + file.Header2.SpeakerArrayOffset, SeekOrigin.Begin);
                file.Speakers = ReadSpeakers(file.Header2.SpeakerCount);
            }

            if (file.Header2.MessageArrayOffset != 0 && file.Header2.MessageCount > 0)
            {
                _reader.BaseStream.Seek(_positionBase + file.Header2.MessageArrayOffset, SeekOrigin.Begin);
                file.Messages = ReadMessages(file.Header2.MessageCount);
            }
        }

        file.FormatVersion = _version;

        return file;
    }

    private Bm2Header ReadHeader()
    {
        var field00 = ReadUInt();
        var magic = _reader.ReadBytes(4);
        if (magic.SequenceEqual(Bm2Header.MAGIC))
        {
            if (_reader.Endianness != Endianness.LittleEndian)
                EndiannessHelper.Swap(ref field00);
            _reader.Endianness = Endianness.LittleEndian;
            _version = BinaryFormatVersion.Version3;
        }
        else if (magic.SequenceEqual(Bm2Header.MAGIC_BE))
        {
            if (_reader.Endianness != Endianness.BigEndian)
                EndiannessHelper.Swap(ref field00);
            _reader.Endianness = Endianness.BigEndian;
            _version = BinaryFormatVersion.Version3BigEndian;
        }

        return new Bm2Header
        {
            Field00 = field00,
            Magic = magic,
            Version = ReadUInt(),
            FileSize = ReadUInt(),
            Header2Offset = ReadUInt()
        };
    }

    private Bm2Header2 ReadHeader2()
    {
        return new Bm2Header2
        {
            SpeakerCount = ReadUInt(),
            SpeakerArrayOffset = ReadUInt(),
            MessageCount = ReadUInt(),
            MessageArrayOffset = ReadUInt()
        };
    }

    private List<Bm2Speaker> ReadSpeakers(uint count)
    {
        var speakers = new List<Bm2Speaker>((int)count);

        for (int i = 0; i < count; i++)
        {
            var speaker = new Bm2Speaker
            {
                Field00 = ReadUInt(),
                DataSize = ReadUInt(),
                DataOffset = ReadUInt(),
                Field0C = ReadUInt()
            };

            if (speaker.Field00 != 0 || speaker.Field0C != 0)
            {
                throw new InvalidDataException($"Invalid speaker data at index {i}");
            }

            if (speaker.DataOffset != 0)
            {
                long currentPos = _reader.BaseStream.Position;
                _reader.BaseStream.Seek(_positionBase + speaker.DataOffset, SeekOrigin.Begin);
                speaker.Data = _reader.ReadBytes((int)speaker.DataSize);
                _reader.BaseStream.Seek(currentPos, SeekOrigin.Begin);
            }

            speakers.Add(speaker);
        }

        return speakers;
    }

    private List<Bm2Message> ReadMessages(uint count)
    {
        var messages = new List<Bm2Message>((int)count);

        for (int i = 0; i < count; i++)
        {
            var message = new Bm2Message
            {
                Name = Encoding.ASCII.GetString(_reader.ReadBytes(32)).TrimEnd('\0'),
                Field30 = ReadUInt(),
                DataSize = ReadUInt(),
                DataOffset = ReadUInt(),
                SpeakerId = ReadUShort(),
                Field3E = ReadUShort(),
                Field40 = ReadUInt(),
                Field44 = ReadUInt(),
                Field48 = ReadUInt(),
                Field4C = ReadUInt()
            };

            ValidateMessage(message, i);

            if (message.DataOffset != 0)
            {
                long currentPos = _reader.BaseStream.Position;
                _reader.BaseStream.Seek(_positionBase + message.DataOffset, SeekOrigin.Begin);
                message.Data = ReadMessageData((int)message.DataSize);
                _reader.BaseStream.Seek(currentPos, SeekOrigin.Begin);
            }

            messages.Add(message);
        }

        return messages;
    }

    private Bm2MessageData ReadMessageData(int dataSize)
    {
        var data = new Bm2MessageData
        {
            PageCount = ReadUInt(),
            PageOffsets = new List<int>()
        };

        for (int i = 0; i < data.PageCount; i++)
        {
            data.PageOffsets.Add((int)ReadUInt());
        }

        data.TextBuffer = _reader.ReadBytes(dataSize - (int)data.PageCount * 4 - 4);
        return data;
    }

    private void ValidateMessage(Bm2Message message, int index)
    {
        if (message.Field30 != 0 || message.Field3E != 0 ||
            message.Field40 != 0 || message.Field44 != 0 ||
            message.Field48 != 0 || message.Field4C != 0)
        {
            throw new InvalidDataException($"Invalid message data at index {index}");
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _reader.Dispose();
            _disposed = true;
        }
    }
}