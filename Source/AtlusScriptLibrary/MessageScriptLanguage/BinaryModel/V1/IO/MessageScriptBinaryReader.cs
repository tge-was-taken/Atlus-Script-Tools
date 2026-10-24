using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.Common.Text.Encodings;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V1;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V1.IO;

public sealed class MessageScriptBinaryReader : IDisposable
{
    private bool mDisposed;
    private readonly long mPositionBase;
    private readonly EndianBinaryReader mReader;
    private BinaryFormatVersion mVersion;
    private bool mVersion0;
    private bool mRelocated;

    public MessageScriptBinaryReader(Stream stream, BinaryFormatVersion version, bool leaveOpen = false)
    {
        mPositionBase = stream.Position;
        mReader = new EndianBinaryReader(stream, ShiftJISEncoding.Instance, leaveOpen, version.HasFlag(BinaryFormatVersion.BigEndian) ? Endianness.BigEndian : Endianness.LittleEndian);
        mVersion = version;
    }

    public MessageScriptBinary ReadBinary()
    {
        var binary = new MessageScriptBinary
        {
            mHeader = ReadHeader()
        };

        binary.mDialogHeaders = ReadDialogHeaders(binary.mHeader);
        binary.mSpeakerTableHeader = ReadSpeakerTableHeader();
        binary.mFormatVersion = mVersion;

        return binary;
    }

    public BinaryHeader ReadHeader()
    {
        var header = new BinaryHeader();

        // Check if the stream isn't too small to be a proper file
        if (mReader.BaseStreamLength < BinaryHeader.SIZE)
        {
            throw new InvalidDataException("Stream is too small to be valid");
        }

        header.FileType = mReader.ReadByte();
        header.Format = mReader.ReadByte();
        header.UserId = mReader.ReadInt16();
        header.FileSize = mReader.ReadInt32();
        header.Magic = mReader.ReadBytes(4);
        header.ExtSize = mReader.ReadInt32();
        header.RelocationTable.Offset = mReader.ReadInt32();
        header.RelocationTableSize = mReader.ReadInt32();
        header.DialogCount = mReader.ReadInt32();
        header.IsRelocated = mReader.ReadByte() != 0;
        mRelocated = header.IsRelocated;
        header.Reserved = mReader.ReadByte();
        header.Version = mReader.ReadInt16();

        // swap endianness
        if (header.Magic.SequenceEqual(BinaryHeader.MAGIC_V1) || header.Magic.SequenceEqual(BinaryHeader.MAGIC_V0))
        {
            mVersion0 = header.Magic.SequenceEqual(BinaryHeader.MAGIC_V0);

            if (mVersion.HasFlag(BinaryFormatVersion.BigEndian))
            {
                SwapHeader(ref header);
                mReader.Endianness = Endianness.LittleEndian;
            }

            mVersion = BinaryFormatVersion.Version1;
        }
        else if (header.Magic.SequenceEqual(BinaryHeader.MAGIC_V1_BE))
        {
            if (!mVersion.HasFlag(BinaryFormatVersion.BigEndian))
            {
                SwapHeader(ref header);
                mReader.Endianness = Endianness.BigEndian;
            }

            mVersion = BinaryFormatVersion.Version1BigEndian;
        }
        else
        {
            throw new InvalidDataException("Header magic value does not match");
        }

        if (header.RelocationTable.Offset != 0)
        {
            mReader.PushPositionAndSeekBegin(mPositionBase + header.RelocationTable.Offset);
            header.RelocationTable.Value = mReader.ReadBytes(header.RelocationTableSize);
            mReader.SeekBeginToPoppedPosition();
        }

        return header;
    }

    private void SwapHeader(ref BinaryHeader header)
    {
        EndiannessHelper.Swap(ref header.UserId);
        EndiannessHelper.Swap(ref header.FileSize);
        EndiannessHelper.Swap(ref header.ExtSize);
        EndiannessHelper.Swap(ref header.RelocationTable.Offset);
        EndiannessHelper.Swap(ref header.RelocationTableSize);
        EndiannessHelper.Swap(ref header.DialogCount);
        EndiannessHelper.Swap(ref header.Version);
    }

    public BinaryDialogHeader[] ReadDialogHeaders(BinaryHeader mHeader)
    {
        BinaryDialogHeader[] headers = new BinaryDialogHeader[mHeader.DialogCount];
        var firstHeaderByAddress = new Dictionary<int, int>();
        int nextAddress = -1;

        for (int i = 0; i < headers.Length; i++)
        {
            ref var header = ref headers[i];
            header.Kind = (BinaryDialogKind)mReader.ReadInt32();
            var offsetPosition = mReader.Position;
            header.Data.Offset = mReader.ReadInt32();

            if (header.Data.Offset != 0)
            {
                var address = Resolve(header.Data.Offset, offsetPosition);

                // Dialogs sharing a name share an address: the original tool resolved the table entry to the
                // first dialog of that name but still wrote this one's own data at its place in the layout.
                if (firstHeaderByAddress.TryGetValue(address, out var first) &&
                    nextAddress >= 0 &&
                    HasSameName(headers[first], nextAddress))
                {
                    header.DataLocation = nextAddress;
                }
                else
                {
                    header.DataLocation = address;
                    if (!firstHeaderByAddress.ContainsKey(address))
                        firstHeaderByAddress.Add(address, i);
                }

                header.Data.Value = ReadDialog(header.Kind, header.DataLocation, out nextAddress);
            }
        }

        return headers;
    }

    // A relocated file stores every pointer relative to the position of the pointer itself, so
    // turn it back into an address counted from the end of the header like the rest of the reader.
    private int Resolve(int value, long fieldPosition)
    {
        if (!mRelocated)
            return value;

        return (int)(fieldPosition - mPositionBase - BinaryHeader.SIZE) + value;
    }

    private bool HasSameName(BinaryDialogHeader header, int address)
    {
        var name = header.Data.Value switch
        {
            BinaryMessageDialog message => message.Name,
            BinarySelectionDialog selection => selection.Name,
            _ => null
        };

        if (name == null || mPositionBase + BinaryHeader.SIZE + address + BinaryMessageDialog.IDENTIFIER_LENGTH > mReader.BaseStreamLength)
            return false;

        mReader.PushPositionAndSeekBegin(mPositionBase + BinaryHeader.SIZE + address);
        var other = mReader.ReadString(StringBinaryFormat.FixedLength, BinaryMessageDialog.IDENTIFIER_LENGTH);
        mReader.SeekBeginToPoppedPosition();
        return name == other;
    }

    public BinarySpeakerTableHeader ReadSpeakerTableHeader()
    {
        BinarySpeakerTableHeader header;

        var offsetPosition = mReader.Position;
        header.SpeakerNameArray.Offset = Resolve(mReader.ReadInt32(), offsetPosition);
        header.SpeakerCount = mReader.ReadInt32();

        // MSG0 stops the speaker table header after the count.
        header.ExtDataOffset = mVersion0 ? 0 : mReader.ReadInt32();
        header.Reserved = mVersion0 ? 0 : mReader.ReadInt32();

        if (header.SpeakerNameArray.Offset != 0)
            header.SpeakerNameArray.Value = ReadSpeakerNames(header.SpeakerNameArray.Offset, header.SpeakerCount);
        else
            header.SpeakerNameArray.Value = null;

        if (header.ExtDataOffset != 0)
            Debug.WriteLine($"{nameof(BinarySpeakerTableHeader)}.{nameof(header.ExtDataOffset)} = {header.ExtDataOffset}");

        if (header.Reserved != 0)
            Debug.WriteLine($"{nameof(BinarySpeakerTableHeader)}.{nameof(header.Reserved)} = {header.Reserved}");

        return header;
    }

    public OffsetTo<List<byte>>[] ReadSpeakerNames(int address, int count)
    {
        mReader.SeekBegin(mPositionBase + BinaryHeader.SIZE + address);

        var addressesPosition = mReader.Position;
        var speakerNameAddresses = mReader.ReadInt32s(count);
        var speakerNames = new OffsetTo<List<byte>>[count];

        for (int i = 0; i < speakerNameAddresses.Length; i++)
        {
            speakerNameAddresses[i] = Resolve(speakerNameAddresses[i], addressesPosition + i * sizeof(int));
            ref int speakerNameAddress = ref speakerNameAddresses[i];

            mReader.SeekBegin(mPositionBase + BinaryHeader.SIZE + speakerNameAddress);
            var bytes = new List<byte>();
            while (true)
            {
                byte b = mReader.ReadByte();
                if (b == 0)
                    break;

                bytes.Add(b);
            }

            speakerNames[i] = new OffsetTo<List<byte>>(speakerNameAddress, bytes);
        }

        return speakerNames;
    }

    private object ReadDialog(BinaryDialogKind type, int address, out int endAddress)
    {
        object dialog;

        mReader.PushPositionAndSeekBegin(mPositionBase + BinaryHeader.SIZE + address);

        switch (type)
        {
            case BinaryDialogKind.Message:
                dialog = ReadMessageDialog();
                break;

            case BinaryDialogKind.Selection:
                dialog = ReadSelectionDialog();
                break;

            default:
                throw new InvalidDataException($"Unknown message type: {type}");
        }

        endAddress = (int)(mReader.Position - mPositionBase - BinaryHeader.SIZE + 3) & ~3;
        mReader.SeekBeginToPoppedPosition();

        return dialog;
    }

    public BinaryMessageDialog ReadMessageDialog()
    {
        BinaryMessageDialog message;

        message.Name = mReader.ReadString(StringBinaryFormat.FixedLength, BinaryMessageDialog.IDENTIFIER_LENGTH);
        message.PageCount = mReader.ReadInt16();
        message.SpeakerId = mReader.ReadUInt16();

        if (message.PageCount > 0)
        {
            var addressesPosition = mReader.Position;
            message.PageStartAddresses = mReader.ReadInt32s(message.PageCount);
            for (int i = 0; i < message.PageCount; i++)
                message.PageStartAddresses[i] = Resolve(message.PageStartAddresses[i], addressesPosition + i * sizeof(int));
            message.TextBufferSize = mReader.ReadInt32();

            // The relocation pass left this one field big endian while swapping the rest to little endian.
            if (mRelocated || message.TextBufferSize < 0 || message.TextBufferSize > 1 << 24)
                EndiannessHelper.Swap(ref message.TextBufferSize);
            message.TextBuffer = mReader.ReadBytes(message.TextBufferSize);
        }
        else
        {
            message.PageStartAddresses = null;
            message.TextBufferSize = 0;
            message.TextBuffer = null;
        }

        return message;
    }

    public BinarySelectionDialog ReadSelectionDialog()
    {
        BinarySelectionDialog message;

        message.Name = mReader.ReadString(StringBinaryFormat.FixedLength, BinaryMessageDialog.IDENTIFIER_LENGTH);
        message.Ext = mReader.ReadInt16();
        message.OptionCount = mReader.ReadInt16();
        message.Pattern = (BinarySelectionDialogPattern)mReader.ReadInt16();
        message.Reserved = mReader.ReadInt16();
        var optionsPosition = mReader.Position;
        message.OptionStartAddresses = mReader.ReadInt32s(message.OptionCount);
        for (int i = 0; i < message.OptionCount; i++)
            message.OptionStartAddresses[i] = Resolve(message.OptionStartAddresses[i], optionsPosition + i * sizeof(int));
        message.TextBufferSize = mReader.ReadInt32();

        // The relocation pass left this one field big endian while swapping the rest to little endian.
        if (mRelocated)
            EndiannessHelper.Swap(ref message.TextBufferSize);

        message.TextBuffer = mReader.ReadBytes(message.TextBufferSize);

        if (message.Ext != 0)
            Debug.WriteLine($"{nameof(BinarySelectionDialog)}.{nameof(message.Ext)} = {message.Ext}");

        if (message.Pattern != 0)
            Debug.WriteLine($"{nameof(BinarySelectionDialog)}.{nameof(message.Pattern)} = {message.Pattern}");

        if (message.Reserved != 0)
            Debug.WriteLine($"{nameof(BinarySelectionDialog)}.{nameof(message.Reserved)} = {message.Reserved}");

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
