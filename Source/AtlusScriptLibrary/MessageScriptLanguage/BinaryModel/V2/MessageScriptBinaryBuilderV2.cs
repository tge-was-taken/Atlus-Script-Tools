using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.Common.Text.Encodings;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2;

public class MessageScriptBinaryV2Builder
{
    // required
    private readonly BinaryFormatVersion mFormatVersion;

    // optional
    private short mUserId;
    private Encoding mEncoding;
    private List<Tuple<BinaryDialogKind, object>> mDialogs;

    // temporary storage
    private readonly List<int> mAddressLocations;   // for generating the relocation table
    private int mPosition;                          // used to calculate addresses
    private readonly List<byte[]> mSpeakerNames;    // for storing the speaker names of dialogue messages

    public MessageScriptBinaryV2Builder(BinaryFormatVersion version)
    {
        mFormatVersion = version;
        mAddressLocations = new List<int>();
        mSpeakerNames = new List<byte[]>();
        mPosition = BinaryHeaderV2.SIZE+BinaryHeader2.SIZE;
        mDialogs = new List<Tuple<BinaryDialogKind, object>>();
        mEncoding = EncodingHelper.GetEncodingForEndianness(Encoding.Unicode, mFormatVersion.HasFlag(BinaryFormatVersion.BigEndian));
    }

    public void SetEncoding(Encoding encoding)
    {
        if (encoding == null) throw new ArgumentNullException(nameof(encoding));
        if (encoding.IsSingleByte)
            throw new ArgumentException($"Single byte encoding not supported", nameof(encoding));
        mEncoding = EncodingHelper.GetEncodingForEndianness(encoding, mFormatVersion.HasFlag(BinaryFormatVersion.BigEndian));
    }

    public void AddDialog(MessageDialog message)
    {
        if (mDialogs == null)
            mDialogs = new List<Tuple<BinaryDialogKind, object>>();

        BinaryMessageDialogV2 binary;

        binary.Type = BinaryDialogKind.Message;
        binary.Name = message.Name.Substring(0, Math.Min(message.Name.Length, BinaryMessageDialogV2.IDENTIFIER_LENGTH));
        binary.PageCount = (ushort)message.Pages.Count;

        if (message.Speaker != null)
        {
            switch (message.Speaker.Kind)
            {
                case SpeakerKind.Named:
                    {
                        //var speakerName = ProcessLine(((NamedSpeaker)message.Speaker).Name);
                        //if (!mSpeakerNames.Any(x => x.SequenceEqual(speakerName)))
                        //    mSpeakerNames.Add(speakerName.ToArray());

                        //binary.SpeakerId = (ushort)mSpeakerNames.FindIndex(x => x.SequenceEqual(speakerName));
                        throw new NotSupportedException("Named speaker not supported");
                    }
                    break;

                case SpeakerKind.Variable:
                    {
                        binary.SpeakerId = (ushort)((VariableSpeaker)message.Speaker).Index;
                    }
                    break;

                default:
                    throw new ArgumentException(nameof(message));
            }
        }
        else
        {
            binary.SpeakerId = 0xFFFF;
        }

        binary.PageStartAddresses = new int[message.Pages.Count];

        var textBuffer = new List<byte>();
        {
            int lineStartAddress = 0x28 + (binary.PageCount * 4);

            for (int i = 0; i < message.Pages.Count; i++)
            {
                binary.PageStartAddresses[i] = lineStartAddress;

                var lineBytes = ProcessLine(message.Pages[i]);
                textBuffer.AddRange(lineBytes);

                lineStartAddress += lineBytes.Count;
            }

            //textBuffer.Add(0);
            //textBuffer.Add(0);
        }

        binary.TextBuffer = textBuffer.ToArray();

        mDialogs.Add(new Tuple<BinaryDialogKind, object>(BinaryDialogKind.Message, binary));
    }

    public void AddDialog(SelectionDialog message)
    {
        if (mDialogs == null)
            mDialogs = new List<Tuple<BinaryDialogKind, object>>();

        BinarySelectionDialogV2 binary;

        binary.Type = BinaryDialogKind.Selection;
        binary.Name = message.Name.Substring(0, Math.Min(message.Name.Length, BinarySelectionDialogV2.IDENTIFIER_LENGTH));
        binary.OptionCount = (ushort)message.Options.Count;
        binary.OptionStartAddresses = new int[message.Options.Count];
        binary.SpeakerId = 0;

        var textBuffer = new List<byte>();
        {
            int lineStartAddress = 0x28 + (binary.OptionCount * 4) + 4;
            for (int i = 0; i < message.Options.Count; i++)
            {
                binary.OptionStartAddresses[i] = lineStartAddress;

                var lineBytes = ProcessLine(message.Options[i]);
                //lineBytes.Add(0); // intentional
                //lineBytes.Add(0); // intentional

                textBuffer.AddRange(lineBytes);

                lineStartAddress += lineBytes.Count;
            }

            //textBuffer.Add(0); // intentional
            //textBuffer.Add(0); // intentional
        }

        binary.TextBuffer = textBuffer.ToArray();
        binary.TextBufferSize = (uint)binary.TextBuffer.Length;

        mDialogs.Add(new Tuple<BinaryDialogKind, object>(BinaryDialogKind.Selection, binary));
    }

    public MessageScriptBinaryV2 Build()
    {
        var binary = new MessageScriptBinaryV2
        {
            mFormatVersion = mFormatVersion
        };

        // note: DONT CHANGE THE ORDER
        binary.mHeader.Magic = mFormatVersion.HasFlag(BinaryFormatVersion.BigEndian) ? BinaryHeaderV2.MAGIC_BE : BinaryHeaderV2.MAGIC;
        binary.mHeader.Version = BinaryHeaderV2.VERSION;
        binary.mHeader2.DialogCount = (ushort)(mDialogs?.Count ?? 0);

        mPosition = BinaryHeaderV2.SIZE;
        AddAddressLocation(); // dialog array offset
        mPosition += 8;
        AddAddressLocation(); // dialog array end offset
        mPosition += 8;

        if (mDialogs?.Any() ?? false)
        {
            // dialog data offsets
            binary.mHeader2.DialogArray.Offset = GetAlignedAddress();
            binary.mHeader2.DialogArray.Value = new OffsetTo<object>[mDialogs.Count];
            for (int i = 0; i < mDialogs.Count; i++)
            {
                AddAddressLocation();
                mPosition += 4;
            }

            // dialog data
            for (int i = 0; i < mDialogs.Count; i++)
            {
                var dialog = mDialogs[i];
                binary.mHeader2.DialogArray.Value[i].Offset = GetAlignedAddress();
                binary.mHeader2.DialogArray.Value[i].Value = dialog.Item2;
                switch (dialog.Item2)
                {
                    case BinaryMessageDialogV2 msg:
                        {
                            var dataOffset = 4 + 32 + 2 + 2;
                            mPosition += dataOffset;
                            var pageAddress = GetAddress();

                            for (int j = 0; j < msg.PageCount; j++)
                            {
                                AddAddressLocation();
                                msg.PageStartAddresses[j] += binary.mHeader2.DialogArray.Value[i].Offset;
                                mPosition += 4;
                            }
                            mPosition += msg.TextBuffer.Length;
                        }
                        break;
                    case BinarySelectionDialogV2 sel:
                        {
                            var dataOffset = 4 + 32 + 2 + 2 + 4;
                            mPosition += dataOffset;
                            var pageAddress = GetAddress();

                            for (int j = 0; j < sel.OptionCount; j++)
                            {
                                AddAddressLocation();
                                sel.OptionStartAddresses[j] += binary.mHeader2.DialogArray.Value[i].Offset;
                                mPosition += 4;
                            }
                            mPosition += sel.TextBuffer.Length;
                        }
                        break;

                    default:
                        break;
                }
            }
        }

        // relocation table
        binary.mHeader2.DialogArrayEndOffset = (uint)GetAlignedAddress();
        binary.mHeader.RelocationTable.Offset = GetAlignedAddress() + BinaryHeaderV2.SIZE;
        binary.mHeader.RelocationTable.Value =
            RelocationTableEncoding.Encode(mAddressLocations, BinaryHeaderV2.SIZE);
        binary.mHeader.RelocationTableSize = (uint)binary.mHeader.RelocationTable.Value.Length;
        mPosition += (int)binary.mHeader.RelocationTableSize;
        binary.mHeader.FileSize = (uint)mPosition;

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
        var text = token.Value;
        var textBytes = mEncoding.GetBytes(text);

        // simple add to the list of bytes
        bytes.AddRange(textBytes);
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

    private void ProcessFunctionToken(FunctionToken token, List<byte> bytes)
    {
        WriteUInt16(bytes, (ushort)token.FunctionIndex);
        foreach (var item in token.Arguments)
            WriteUInt16(bytes, item);
    }

    private void ProcessCodePoint(CodePointToken token, List<byte> bytes)
    {
        if (token.Bytes.Count == 2)
        {
            WriteUInt16(bytes, (ushort)(token.Bytes[0] << 8 | token.Bytes[1]));
        }
        else
        {
            bytes.AddRange(token.Bytes);
        }
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
        return mPosition - BinaryHeaderV2.SIZE;
    }

    private int GetAlignedAddress()
    {
        AlignPosition();
        return GetAddress();
    }
}
