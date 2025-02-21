using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.Common.Text.Encodings;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2.IO;

public sealed class MessageScriptBinaryV2Reader : IDisposable
{
    private bool mDisposed;
    private readonly long mPositionBase;
    private readonly EndianBinaryReader mReader;
    private BinaryFormatVersion mVersion;

    public MessageScriptBinaryV2Reader(Stream stream, BinaryFormatVersion version, bool leaveOpen = false)
    {
        mPositionBase = stream.Position;
        mReader = new EndianBinaryReader(stream, ShiftJISEncoding.Instance, leaveOpen, version.HasFlag(BinaryFormatVersion.BigEndian) ? Endianness.BigEndian : Endianness.LittleEndian);
        mVersion = version;
    }

    public MessageScriptBinaryV2 ReadBinary()
    {
        var binary = new MessageScriptBinaryV2
        {
            mHeader = ReadHeader(),
            mHeader2 = ReadHeader2()
        };

        binary.mFormatVersion = mVersion;

        return binary;
    }

    public BinaryHeaderV2 ReadHeader()
    {
        var header = new BinaryHeaderV2();

        if (mReader.BaseStreamLength < BinaryHeaderV2.SIZE)
        {
            throw new InvalidDataException("Stream is too small to be valid");
        }

        header.Magic = mReader.ReadBytes(BinaryHeaderV2.MAGIC_BE.Length);
        if (!header.Magic.SequenceEqual(BinaryHeaderV2.MAGIC_BE))
        {
            if (header.Magic.SequenceEqual(BinaryHeaderV2.MAGIC))
            {
                mReader.Endianness = Endianness.LittleEndian;
                mVersion = BinaryFormatVersion.Version2;
            }
            else
            {
                throw new InvalidDataException("Invalid magic value in header");
            }
        }
        else
        {
            mReader.Endianness = Endianness.BigEndian;
            mVersion = BinaryFormatVersion.Version2BigEndian;
        }

        header.Version = mReader.ReadUInt32();
        header.Field0C = mReader.ReadUInt32();
        header.FileSize = mReader.ReadUInt32();
        header.RelocationTable.Offset = mReader.ReadInt32();
        header.RelocationTableSize = mReader.ReadUInt32();

        Trace.Assert(header.Version == BinaryHeaderV2.VERSION);
        Trace.Assert(header.Field0C == 0);

        if (header.RelocationTable.Offset != 0)
        {
            mReader.PushPositionAndSeekBegin(mPositionBase + header.RelocationTable.Offset);
            header.RelocationTable.Value = mReader.ReadBytes((int)header.RelocationTableSize);
            mReader.SeekBeginToPoppedPosition();
        }

        return header;
    }

    public BinaryHeader2 ReadHeader2()
    {
        var header = new BinaryHeader2();

        header.DialogArray.Offset = mReader.ReadInt32();
        header.DialogCount = mReader.ReadUInt32();
        header.DialogArrayEndOffset = mReader.ReadUInt32();
        header.Field28 = mReader.ReadUInt32();

        Trace.Assert(header.Field28 == 0);

        if (header.DialogArray.Offset != 0)
        {
            mReader.PushPositionAndSeekBegin(mPositionBase + header.DialogArray.Offset + BinaryHeaderV2.SIZE);
            header.DialogArray.Value = ReadDialogArray(header);
            mReader.SeekBeginToPoppedPosition();
        }

        return header;
    }

    public OffsetTo<object>[] ReadDialogArray(BinaryHeader2 header)
    {
        var result = new List<OffsetTo<object>>();
        for (int i = 0; i < header.DialogCount; i++)
        {
            OffsetTo<object> dialog;
            dialog.Offset = mReader.ReadInt32();
            dialog.Value = null;
            int nextOffset;
            if (i + 1 < header.DialogCount)
            {
                nextOffset = mReader.ReadInt32();
                mReader.SeekCurrent(-4);
            }
            else
            {
                nextOffset = (int)header.DialogArrayEndOffset;
            }

            if (dialog.Offset != 0)
            {
                mReader.PushPositionAndSeekBegin(mPositionBase + dialog.Offset + BinaryHeaderV2.SIZE);
                dialog.Value = ReadDialog(mPositionBase + nextOffset + BinaryHeaderV2.SIZE);
                mReader.SeekBeginToPoppedPosition();
            }
            result.Add(dialog);
        }

        return result.ToArray();
    }

    private object ReadDialog(long nextOffset)
    {
        object dialog;

        var type = (BinaryDialogKind)mReader.ReadUInt32();

        switch (type)
        {
            case BinaryDialogKind.Message:
                dialog = ReadMessageDialog(nextOffset);
                break;

            case BinaryDialogKind.Selection:
                dialog = ReadSelectionDialog(nextOffset);
                break;

            default:
                throw new InvalidDataException($"Unknown message type: {type}");
        }

        return dialog;
    }

    public BinaryMessageDialogV2 ReadMessageDialog(long nextOffset)
    {
        BinaryMessageDialogV2 message;

        message.Type = BinaryDialogKind.Message;
        message.Name = mReader.ReadString(StringBinaryFormat.FixedLength, BinaryMessageDialogV2.IDENTIFIER_LENGTH);
        message.PageCount = mReader.ReadUInt16();
        message.SpeakerId = mReader.ReadUInt16();
        message.PageStartAddresses = mReader.ReadInt32s(message.PageCount);
        var textBufferSize = nextOffset - mReader.Position - mPositionBase;
        message.TextBuffer = mReader.ReadBytes((int)textBufferSize);

        return message;
    }

    public BinarySelectionDialogV2 ReadSelectionDialog(long nextOffset)
    {
        BinarySelectionDialogV2 message;

        message.Type = BinaryDialogKind.Selection;
        message.Name = mReader.ReadString(StringBinaryFormat.FixedLength, BinaryMessageDialogV2.IDENTIFIER_LENGTH);
        message.OptionCount = mReader.ReadUInt16();
        message.SpeakerId = mReader.ReadUInt16();
        message.OptionStartAddresses = mReader.ReadInt32s(message.OptionCount);
        message.TextBufferSize = mReader.ReadUInt32();
        message.TextBuffer = mReader.ReadBytes((int)message.TextBufferSize);

        Trace.Assert(message.SpeakerId == 0);

        return message;
    }

    public void Dispose()
    {
        if (mDisposed)
            return;

        mReader.Dispose();

        mDisposed = true;
    }
}
