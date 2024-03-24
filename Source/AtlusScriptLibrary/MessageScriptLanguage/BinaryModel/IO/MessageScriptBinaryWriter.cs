using AtlusScriptLibrary.Common.IO;
using System;
using System.IO;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.IO;

public sealed class MessageScriptBinaryWriter : IDisposable
{
    private bool mDisposed;
    private readonly long mPositionBase;
    private readonly EndianBinaryWriter mWriter;

    public MessageScriptBinaryWriter(Stream stream, BinaryFormatVersion version, bool leaveOpen = false)
    {
        mPositionBase = stream.Position;
        mWriter = new EndianBinaryWriter(stream, Encoding.GetEncoding(932), leaveOpen, version.HasFlag(BinaryFormatVersion.BigEndian) ? Endianness.BigEndian : Endianness.LittleEndian);
    }

    public void Dispose()
    {
        if (mDisposed)
            return;

        ((IDisposable)mWriter).Dispose();

        mDisposed = true;
    }

    public void WriteBinary(MessageScriptBinary binary)
    {
        WriteHeader(ref binary.mHeader);
        WriteDialogHeaders(binary.mDialogHeaders);
        WriteSpeakerHeader(ref binary.mSpeakerTableHeader);
        WriteDialogs(binary.mDialogHeaders);
        WriteSpeakerNameOffsets(ref binary.mSpeakerTableHeader);
        WriteSpeakerNames(ref binary.mSpeakerTableHeader);
        WriteRelocationTable(ref binary.mHeader.RelocationTable);
    }

    private void WriteHeader(ref BinaryHeader header)
    {
        mWriter.Write(header.FileType);
        mWriter.Write(header.Format);
        mWriter.Write(header.UserId);
        mWriter.Write(header.FileSize);
        mWriter.Write(header.Magic);
        mWriter.Write(header.ExtSize);
        mWriter.Write(header.RelocationTable.Offset);
        mWriter.Write(header.RelocationTableSize);
        mWriter.Write(header.DialogCount);
        mWriter.Write(header.IsRelocated ? (short)1 : (short)0);
        mWriter.Write(header.Version);
    }

    private void WriteDialogHeaders(BinaryDialogHeader[] headers)
    {
        foreach (var header in headers)
        {
            mWriter.Write((int)header.Kind);
            mWriter.Write(header.Data.Offset);
        }
    }

    private void WriteSpeakerHeader(ref BinarySpeakerTableHeader header)
    {
        mWriter.Write(header.SpeakerNameArray.Offset);
        mWriter.Write(header.SpeakerCount);
        mWriter.Write(header.ExtDataOffset);
        mWriter.Write(header.Reserved);
    }

    private void WriteDialogs(BinaryDialogHeader[] headers)
    {
        foreach (var header in headers)
        {
            mWriter.SeekBegin(mPositionBase + BinaryHeader.SIZE + header.Data.Offset);

            switch (header.Kind)
            {
                case BinaryDialogKind.Message:
                    WriteMessageDialog((BinaryMessageDialog)header.Data.Value);
                    break;

                case BinaryDialogKind.Selection:
                    WriteSelectionDialog((BinarySelectionDialog)header.Data.Value);
                    break;

                default:
                    throw new NotImplementedException(header.Kind.ToString());
            }
        }
    }

    private void WriteMessageDialog(BinaryMessageDialog dialogue)
    {
        mWriter.Write(dialogue.Name.Substring(0, Math.Min(dialogue.Name.Length, BinaryMessageDialog.IDENTIFIER_LENGTH)),
                       StringBinaryFormat.FixedLength, BinaryMessageDialog.IDENTIFIER_LENGTH);
        mWriter.Write(dialogue.PageCount);
        mWriter.Write(dialogue.SpeakerId);

        if (dialogue.PageCount > 0)
        {
            mWriter.Write(dialogue.PageStartAddresses);
            mWriter.Write(dialogue.TextBufferSize);
            mWriter.Write(dialogue.TextBuffer);
        }
    }

    private void WriteSelectionDialog(BinarySelectionDialog selection)
    {
        mWriter.Write(selection.Name.Substring(0, Math.Min(selection.Name.Length, BinarySelectionDialog.IDENTIFIER_LENGTH)),
                       StringBinaryFormat.FixedLength, BinaryMessageDialog.IDENTIFIER_LENGTH);
        mWriter.Write(selection.Ext);
        mWriter.Write(selection.OptionCount);
        mWriter.Write((short)selection.Pattern);
        mWriter.Write(selection.Reserved);
        mWriter.Write(selection.OptionStartAddresses);
        mWriter.Write(selection.TextBufferSize);
        mWriter.Write(selection.TextBuffer);
    }

    private void WriteSpeakerNameOffsets(ref BinarySpeakerTableHeader header)
    {
        mWriter.SeekBegin(mPositionBase + BinaryHeader.SIZE + header.SpeakerNameArray.Offset);
        foreach (var speakerName in header.SpeakerNameArray.Value)
            mWriter.Write(speakerName.Offset);
    }

    private void WriteSpeakerNames(ref BinarySpeakerTableHeader header)
    {
        foreach (var speakerName in header.SpeakerNameArray.Value)
        {
            mWriter.SeekBegin(mPositionBase + BinaryHeader.SIZE + speakerName.Offset);
            mWriter.Write(speakerName.Value.ToArray());
            mWriter.Write((byte)0);
        }
    }

    private void WriteRelocationTable(ref OffsetTo<byte[]> relocationTable)
    {
        mWriter.SeekBegin(mPositionBase + relocationTable.Offset);
        mWriter.Write(relocationTable.Value);
    }
}