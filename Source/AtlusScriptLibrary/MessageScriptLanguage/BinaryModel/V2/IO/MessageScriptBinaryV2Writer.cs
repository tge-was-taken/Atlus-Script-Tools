using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.Common.Text.Encodings;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2.IO;

public sealed class MessageScriptBinaryV2Writer : IDisposable
{
    private bool mDisposed;
    private readonly long mPositionBase;
    private readonly EndianBinaryWriter mWriter;

    public MessageScriptBinaryV2Writer(Stream stream, BinaryFormatVersion version, bool leaveOpen = false)
    {
        mPositionBase = stream.Position;
        mWriter = new EndianBinaryWriter(stream, ShiftJISEncoding.Instance, leaveOpen, version.HasFlag(BinaryFormatVersion.BigEndian) ? Endianness.BigEndian : Endianness.LittleEndian);
    }

    public void WriteBinary(MessageScriptBinaryV2 binary)
    {
        WriteHeader(binary.mHeader);
        WriteHeader2(binary.mHeader2);
        WriteDialogEntries(binary.mHeader2);
        WriteRelocationTable(binary.mHeader);
    }

    public void WriteHeader(BinaryHeaderV2 header)
    {
        mWriter.Write(header.Magic);
        mWriter.Write(header.Version);
        mWriter.Write(header.Field0C);
        mWriter.Write(header.FileSize);
        mWriter.Write(header.RelocationTable.Offset);
        mWriter.Write(header.RelocationTableSize);
    }

    public void WriteHeader2(BinaryHeader2 header)
    {
        mWriter.Write(header.DialogArray.Offset);
        mWriter.Write(header.DialogCount);
        mWriter.Write(header.DialogArrayEndOffset);
        mWriter.Write(header.Field28);
    }

    private void WriteDialogEntries(BinaryHeader2 header)
    {
        if (header.DialogArray.Offset != 0 && header.DialogArray.Value != null)
        {
            mWriter.SeekBegin(mPositionBase + header.DialogArray.Offset + BinaryHeaderV2.SIZE);
            WriteDialogArray(header.DialogArray.Value);
        }
    }

    public void WriteDialogArray(OffsetTo<object>[] dialogs)
    {
        foreach (var dialog in dialogs)
        {
            mWriter.Write(dialog.Offset);
            var nextPos = mWriter.Position;
            if (dialog.Value != null)
            {
                mWriter.SeekBegin(mPositionBase + BinaryHeaderV2.SIZE + dialog.Offset);
                WriteDialog(dialog.Value);
            }
            mWriter.SeekBegin(nextPos);
        }
    }

    private void WriteDialog(object dialog)
    {
        switch (dialog)
        {
            case BinaryMessageDialogV2 message:
                WriteMessageDialog(message);
                break;

            case BinarySelectionDialogV2 selection:
                WriteSelectionDialog(selection);
                break;

            default:
                throw new InvalidDataException($"Unknown dialog type: {dialog.GetType()}");
        }
    }

    public void WriteMessageDialog(BinaryMessageDialogV2 message)
    {
        mWriter.Write((uint)message.Type);
        mWriter.Write(message.Name.Substring(0, Math.Min(message.Name.Length, BinarySelectionDialogV2.IDENTIFIER_LENGTH)),
                       StringBinaryFormat.FixedLength, BinarySelectionDialogV2.IDENTIFIER_LENGTH);
        mWriter.Write(message.PageCount);
        mWriter.Write(message.SpeakerId);
        mWriter.Write(message.PageStartAddresses);
        mWriter.Write(message.TextBuffer);
    }

    public void WriteSelectionDialog(BinarySelectionDialogV2 selection)
    {
        mWriter.Write((uint)selection.Type);
        mWriter.Write(selection.Name.Substring(0, Math.Min(selection.Name.Length, BinarySelectionDialogV2.IDENTIFIER_LENGTH)),
                       StringBinaryFormat.FixedLength, BinarySelectionDialogV2.IDENTIFIER_LENGTH);
        mWriter.Write(selection.OptionCount);
        mWriter.Write(selection.SpeakerId);
        mWriter.Write(selection.OptionStartAddresses);
        mWriter.Write(selection.TextBufferSize);
        mWriter.Write(selection.TextBuffer);
    }

    private void WriteRelocationTable(BinaryHeaderV2 header)
    {
        if (header.RelocationTable.Offset != 0 && header.RelocationTable.Value != null)
        {
            mWriter.SeekBegin(mPositionBase + header.RelocationTable.Offset);
            mWriter.Write(header.RelocationTable.Value);
        }
    }

    public void Dispose()
    {
        if (mDisposed)
            return;

        mWriter.Dispose();

        mDisposed = true;
    }
}
