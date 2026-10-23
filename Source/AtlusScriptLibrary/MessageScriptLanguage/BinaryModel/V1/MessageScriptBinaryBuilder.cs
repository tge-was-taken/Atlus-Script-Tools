using AtlusScriptLibrary.Common.IO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V1;

public class MessageScriptBinaryBuilder
{
    // required
    private readonly BinaryFormatVersion mFormatVersion;

    // optional
    private short mUserId;
    private bool mVersion0;
    private bool mRelocated;
    private Encoding mEncoding;
    private List<Tuple<BinaryDialogKind, object>> mDialogs;

    // temporary storage
    private readonly List<int> mAddressLocations;   // for generating the relocation table
    private int mPosition;                          // used to calculate addresses
    private readonly List<byte[]> mSpeakerNames;    // for storing the speaker names of dialogue messages
    private readonly List<string> mDialogNames;     // untruncated dialog names, for resolving repeated names

    public MessageScriptBinaryBuilder(BinaryFormatVersion version)
    {
        mFormatVersion = version;
        mAddressLocations = new List<int>();
        mSpeakerNames = new List<byte[]>();
        mDialogNames = new List<string>();
        mPosition = BinaryHeader.SIZE;
        mDialogs = new List<Tuple<BinaryDialogKind, object>>();
    }

    public void SetUserId(short value)
    {
        mUserId = value;
    }

    public void SetVersion0(bool value)
    {
        mVersion0 = value;
    }

    public void SetRelocated(bool value)
    {
        mRelocated = value;
    }

    internal void SetEncoding(Encoding encoding)
    {
        mEncoding = encoding;
    }

    public void AddDialog(MessageDialog message)
    {
        if (mDialogs == null)
            mDialogs = new List<Tuple<BinaryDialogKind, object>>();

        BinaryMessageDialog binary;

        binary.Name = message.Name.Substring(0, Math.Min(message.Name.Length, BinaryMessageDialog.IDENTIFIER_LENGTH));
        binary.PageCount = (short)message.Pages.Count;

        if (message.Speaker != null)
        {
            switch (message.Speaker.Kind)
            {
                case SpeakerKind.Named:
                    {
                        var name = ((NamedSpeaker)message.Speaker).Name;
                        var speakerName = ProcessLine(name);

                        // Little endian version 1 shares a table entry for any equal name, while the
                        // later tools only share plain text and give a name with function tokens its own.
                        var shareable = mFormatVersion.HasFlag(BinaryFormatVersion.Version1) &&
                                        !mFormatVersion.HasFlag(BinaryFormatVersion.BigEndian) ||
                                        name.Tokens.All(x => x.Kind != TokenKind.Function) ||
                                        message.ShareSpeakerName;
                        var index = shareable ? mSpeakerNames.FindIndex(x => x.SequenceEqual(speakerName)) : -1;
                        if (index == -1)
                        {
                            index = mSpeakerNames.Count;
                            mSpeakerNames.Add(speakerName.ToArray());
                        }

                        binary.SpeakerId = (ushort)index;
                    }
                    break;

                case SpeakerKind.Variable:
                    {
                        binary.SpeakerId = (ushort)(0x8000u | ((VariableSpeaker)message.Speaker).Index);
                    }
                    break;

                default:
                    throw new ArgumentException(nameof(message));
            }
        }
        else
        {
            // A dialog without pages stores 0 here, not the usual no-speaker sentinel.
            binary.SpeakerId = (ushort)(binary.PageCount == 0 ? 0 : 0xFFFF);
        }

        binary.PageStartAddresses = new int[message.Pages.Count];

        var textBuffer = new List<byte>();
        {
            int lineStartAddress = 0x1C + binary.PageCount * 4 + 4;

            for (int i = 0; i < message.Pages.Count; i++)
            {
                binary.PageStartAddresses[i] = lineStartAddress;

                var lineBytes = ProcessLine(message.Pages[i]);
                textBuffer.AddRange(lineBytes);

                lineStartAddress += lineBytes.Count;
            }

            if (binary.PageCount > 0 && !message.OmitTrailingTerminator)
                textBuffer.Add(0);
        }

        binary.TextBuffer = textBuffer.ToArray();
        binary.TextBufferSize = binary.TextBuffer.Length;

        mDialogNames.Add(message.Name);
        mDialogs.Add(new Tuple<BinaryDialogKind, object>(BinaryDialogKind.Message, binary));
    }

    public void AddDialog(SelectionDialog message)
    {
        if (mDialogs == null)
            mDialogs = new List<Tuple<BinaryDialogKind, object>>();

        BinarySelectionDialog binary;

        binary.Name = message.Name.Substring(0, Math.Min(message.Name.Length, BinarySelectionDialog.IDENTIFIER_LENGTH));
        binary.Pattern = (BinarySelectionDialogPattern)message.Pattern;
        binary.Ext = binary.Reserved = 0;
        binary.OptionCount = (short)message.Options.Count;
        binary.OptionStartAddresses = new int[message.Options.Count];

        var textBuffer = new List<byte>();
        {
            int lineStartAddress = 0x20 + binary.OptionCount * 4 + 4;
            for (int i = 0; i < message.Options.Count; i++)
            {
                binary.OptionStartAddresses[i] = lineStartAddress;

                var lineBytes = ProcessLine(message.Options[i]);
                lineBytes.Add(0); // intentional

                textBuffer.AddRange(lineBytes);

                lineStartAddress += lineBytes.Count;
            }

            if (!message.OmitTrailingTerminator)
                textBuffer.Add(0); // intentional
        }

        binary.TextBuffer = textBuffer.ToArray();
        binary.TextBufferSize = binary.TextBuffer.Length;

        mDialogNames.Add(message.Name);
        mDialogs.Add(new Tuple<BinaryDialogKind, object>(BinaryDialogKind.Selection, binary));
    }

    public MessageScriptBinary Build()
    {
        var binary = new MessageScriptBinary
        {
            // A relocated file is always little endian, whatever endianness the format version asks for.
            mFormatVersion = mRelocated ? mFormatVersion & ~BinaryFormatVersion.BigEndian : mFormatVersion
        };

        // note: DONT CHANGE THE ORDER
        BuildHeaderFirstPass(ref binary.mHeader);

        if (mDialogs != null)
        {
            BuildWindowHeadersFirstPass(ref binary.mDialogHeaders);

            BuildSpeakerTableHeaderFirstPass(ref binary.mSpeakerTableHeader);

            BuildWindowHeadersFinalPass(ref binary.mDialogHeaders);

            BuildSpeakerTableHeaderSecondPass(ref binary.mSpeakerTableHeader);

            BuildSpeakerTableHeaderFinalPass(ref binary.mSpeakerTableHeader);
        }

        BuildHeaderFinalPass(ref binary.mHeader);

        return binary;
    }

    private List<byte> ProcessLine(TokenText line)
    {
        List<byte> bytes = new List<byte>();

        foreach (var token in line.Tokens)
        {
            ProcessToken(token, bytes);
        }

        return bytes;
    }

    private void ProcessToken(IToken token, List<byte> bytes)
    {
        switch (token.Kind)
        {
            case TokenKind.String:
                ProcessTextToken((StringToken)token, bytes);
                break;

            case TokenKind.Function:
                ProcessFunctionToken((FunctionToken)token, bytes);
                break;

            case TokenKind.CodePoint:
                ProcessCodePoint((CodePointToken)token, bytes);
                break;

            case TokenKind.NewLine:
                bytes.Add(NewLineToken.ASCIIValue);
                break;

            default:
                throw new NotImplementedException(token.Kind.ToString());
        }
    }

    private void ProcessTextToken(StringToken token, List<byte> bytes)
    {
        byte[] textBytes;
        if (mEncoding != null)
        {
            textBytes = mEncoding.GetBytes(token.Value);
        }
        else
        {
            textBytes = Encoding.ASCII.GetBytes(token.Value);
        }

        // simple add to the list of bytes
        bytes.AddRange(textBytes);
    }

    private void ProcessFunctionToken(FunctionToken token, List<byte> bytes)
    {
        // AAAA BBBB where A is a signifier value for a function and B is the encoded argument byte size
        byte functionSignifier;

        // Version1DDS carries the Version1 flag, so it has to be tested first.
        if (mFormatVersion.HasFlag(BinaryFormatVersion.Version1DDS))
        {
            byte argumentByteCount = (byte)(token.Arguments.Count * 2 & 0x0F);
            if (argumentByteCount == 0)
                argumentByteCount = 1; // tested

            functionSignifier = (byte)(0xF0 | argumentByteCount);
        }
        else if (mFormatVersion.HasFlag(BinaryFormatVersion.Version1))
        {
            functionSignifier = (byte)(0xF0 | token.Arguments.Count * sizeof(short) / 2 + 1 & 0x0F);
        }
        else
        {
            throw new NotImplementedException(mFormatVersion.ToString());
        }

        // AAAB BBBB where A is the table index and B is the function index
        byte functionId = (byte)((token.FunctionTableIndex & 0x07) << 5 | token.FunctionIndex & 0x1F);

        byte[] argumentBytes = new byte[token.Arguments.Count * 2];

        for (int i = 0; i < token.Arguments.Count; i++)
        {
            // arguments are stored in little endian regardless of the rest of the format
            byte firstByte = (byte)((token.Arguments[i] & 0xFF) + 1);
            byte secondByte = (byte)(((token.Arguments[i] & 0xFF00) >> 8) + 1);

            int byteIndex = i * sizeof(short);
            argumentBytes[byteIndex] = firstByte;
            argumentBytes[byteIndex + 1] = secondByte;
        }
        if (token.UseIdentifierByte) bytes.Add(0xfe);
        bytes.Add(functionSignifier);
        bytes.Add(functionId);
        bytes.AddRange(argumentBytes);
    }

    private void ProcessCodePoint(CodePointToken token, List<byte> bytes)
    {
        bytes.AddRange(token.Bytes);
    }

    private void BuildHeaderFirstPass(ref BinaryHeader header)
    {
        header.FileType = BinaryHeader.FILE_TYPE;
        header.Format = 0;
        header.UserId = mUserId;
        header.Magic = mFormatVersion.HasFlag(BinaryFormatVersion.BigEndian) && !mRelocated ? BinaryHeader.MAGIC_V1_BE
            : mVersion0 ? BinaryHeader.MAGIC_V0
            : BinaryHeader.MAGIC_V1;
        header.ExtSize = 0;
        header.DialogCount = mDialogs?.Count ?? 0;
        header.IsRelocated = mRelocated;

        // The values the only known MSG0 file carries here.
        header.Reserved = (byte)(mVersion0 ? 0x49 : 0);
        header.Version = (short)(mVersion0 ? 0x40 : 2);
    }

    private void BuildWindowHeadersFirstPass(ref BinaryDialogHeader[] headers)
    {
        headers = new BinaryDialogHeader[mDialogs.Count];
        for (int i = 0; i < headers.Length; i++)
        {
            headers[i].Kind = mDialogs[i].Item1;
            MoveToNextIntPosition();

            AddAddressLocation();
            MoveToNextIntPosition();
        }
    }

    private void BuildSpeakerTableHeaderFirstPass(ref BinarySpeakerTableHeader speakerHeader)
    {
        AddAddressLocation();
        MoveToNextIntPosition();

        speakerHeader.SpeakerCount = mSpeakerNames.Count;
        MoveToNextIntPosition();

        speakerHeader.ExtDataOffset = 0;
        speakerHeader.Reserved = 0;

        // MSG0 stops the speaker table header after the name array pointer and the count.
        if (!mVersion0)
        {
            MoveToNextIntPosition();
            MoveToNextIntPosition();
        }
    }

    private void BuildWindowHeadersFinalPass(ref BinaryDialogHeader[] headers)
    {
        var firstByName = new Dictionary<string, SharedDialogAddresses>();

        for (int i = 0; i < headers.Length; i++)
        {
            headers[i].DataLocation = GetAlignedAddress();

            // A dialog repeating an earlier dialog's name still gets its own data, but the table entry and
            // the addresses within it point at the first dialog of that name.
            if (!firstByName.TryGetValue(mDialogNames[i], out var first))
            {
                first = new SharedDialogAddresses { Address = headers[i].DataLocation };
                firstByName.Add(mDialogNames[i], first);
            }

            headers[i].Data.Offset = first.Address;
            headers[i].Data.Value = UpdateDialogPageAddresses(
                mDialogs[i].Item2, headers[i].DataLocation, first);
        }
    }

    /// <summary>
    /// The data address and page address array that every dialog of one name emits. Each dialog fills
    /// the entries that are not there yet from its own text, so a later one reuses what it finds.
    /// </summary>
    private sealed class SharedDialogAddresses
    {
        public int Address;
        public readonly List<int> PageAddresses = new();
    }

    private static void SharePageAddresses(int[] pageAddresses, int dataLocation, int textBufferSize,
        int textBufferOffset, SharedDialogAddresses shared)
    {
        for (int i = 0; i < pageAddresses.Length; i++)
        {
            if (i == shared.PageAddresses.Count)
                shared.PageAddresses.Add(dataLocation + pageAddresses[i]);

            pageAddresses[i] = shared.PageAddresses[i];
        }

        // Each dialog also leaves an entry at its terminator, which a later dialog of the same name
        // emits as the start of the page after the last one this dialog has.
        if (pageAddresses.Length == shared.PageAddresses.Count)
            shared.PageAddresses.Add(dataLocation + textBufferOffset + textBufferSize - 1);
    }

    /// <summary>
    /// Where a dialog's text buffer starts, counted from the start of the dialog's data.
    /// </summary>
    private static int GetTextBufferOffset(object dialog) => dialog switch
    {
        BinaryMessageDialog message => 0x1C + (message.PageCount * sizeof(int)) + sizeof(int),
        BinarySelectionDialog selection => 0x20 + (selection.OptionCount * sizeof(int)) + sizeof(int),
        _ => throw new NotImplementedException(dialog.GetType().ToString())
    };

    private void BuildSpeakerTableHeaderSecondPass(ref BinarySpeakerTableHeader speakerTableHeader)
    {
        speakerTableHeader.SpeakerNameArray.Offset = GetAlignedAddress();
        for (int i = 0; i < speakerTableHeader.SpeakerCount; i++)
        {
            AddAddressLocation();
            MoveToNextIntPosition();
        }
    }

    private void BuildSpeakerTableHeaderFinalPass(ref BinarySpeakerTableHeader speakerTableHeader)
    {
        speakerTableHeader.SpeakerNameArray.Value = new OffsetTo<List<byte>>[speakerTableHeader.SpeakerCount];
        for (int i = 0; i < speakerTableHeader.SpeakerNameArray.Value.Length; i++)
        {
            speakerTableHeader.SpeakerNameArray.Value[i].Offset = GetAddress();
            speakerTableHeader.SpeakerNameArray.Value[i].Value = mSpeakerNames[i].ToList();

            // todo: maybe the speakername should include the trailing 0
            MoveToNextPositionByOffset(mSpeakerNames[i].Length + 1);
        }
    }

    private void BuildHeaderFinalPass(ref BinaryHeader header)
    {
        header.RelocationTable.Offset = GetAlignedAddress() + BinaryHeader.SIZE;
        header.RelocationTable.Value =
            RelocationTableEncoding.Encode(mAddressLocations, BinaryHeader.SIZE);
        header.RelocationTableSize = header.RelocationTable.Value.Length;
        mPosition += header.RelocationTableSize;

        header.FileSize = mPosition;
    }

    private object UpdateDialogPageAddresses(object dialog, int dataLocation,
        SharedDialogAddresses shared)
    {
        switch (dialog)
        {
            case BinaryMessageDialog dialogue:
                {
                    mPosition += 0x1C;

                    // A dialog without pages ends after the speaker field.
                    if (dialogue.PageCount > 0)
                    {
                        SharePageAddresses(dialogue.PageStartAddresses, dataLocation,
                            dialogue.TextBufferSize, GetTextBufferOffset(dialogue), shared);

                        for (int i = 0; i < dialogue.PageStartAddresses.Length; i++)
                        {
                            AddAddressLocation();
                            mPosition += 4;
                        }

                        mPosition += 4 + dialogue.TextBufferSize;
                    }
                }
                break;

            case BinarySelectionDialog selection:
                {
                    mPosition += 0x20;

                    SharePageAddresses(selection.OptionStartAddresses, dataLocation,
                        selection.TextBufferSize, GetTextBufferOffset(selection), shared);

                    for (int i = 0; i < selection.OptionStartAddresses.Length; i++)
                    {
                        AddAddressLocation();
                        mPosition += 4;
                    }

                    mPosition += 4 + selection.TextBufferSize;
                }
                break;

            default:
                throw new NotImplementedException(dialog.GetType().ToString());
        }

        return dialog;
    }

    private void MoveToNextIntPosition()
    {
        mPosition += sizeof(int);
    }

    private void MoveToNextPositionByOffset(int offset)
    {
        mPosition += offset;
    }

    private void AddAddressLocation()
    {
        mAddressLocations.Add(mPosition);
    }

    private void AlignPosition()
    {
        mPosition = mPosition + 3 & ~3;
    }

    private int GetAddress()
    {
        return mPosition - BinaryHeader.SIZE;
    }

    private int GetAlignedAddress()
    {
        AlignPosition();
        return GetAddress();
    }
}
