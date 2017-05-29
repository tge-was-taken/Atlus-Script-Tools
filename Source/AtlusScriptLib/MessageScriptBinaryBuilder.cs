using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AtlusScriptLib.Common.IO;

namespace AtlusScriptLib
{
    public class MessageScriptBinaryBuilder
    {
        // required
        private readonly MessageScriptBinaryFormatVersion mFormatVersion;

        // optional
        private short mUserId;
        private List<Tuple<MessageScriptBinaryMessageType, object>> mMessages;

        // temporary storage
        private readonly List<int> mAddressLocations;   // for generating the relocation table
        private int mPosition;                          // used to calculate addresses
        private readonly List<byte[]> mSpeakerNames;    // for storing the speaker names of dialogue messages

        public MessageScriptBinaryBuilder(MessageScriptBinaryFormatVersion version)
        {
            mFormatVersion = version;
            mAddressLocations = new List<int>();
            mSpeakerNames = new List<byte[]>();
            mPosition = MessageScriptBinaryHeader.SIZE;
        }

        public void SetUserId(short value)
        {
            mUserId = value;
        }

        public void AddMessage(MessageScriptDialogueMessage message)
        {
            if (mMessages == null)
                mMessages = new List<Tuple<MessageScriptBinaryMessageType, object>>();

            MessageScriptBinaryDialogueMessage binary;

            binary.Identifier = message.Identifier;
            binary.LineCount = (short)message.Lines.Count;

            if (message.Speaker != null)
            {
                switch (message.Speaker.Type)
                {
                    case MessageScriptDialogueMessageSpeakerType.Named:
                        {
                            var speakerName = ProcessMessageLine(((MessageScriptDialogueMessageNamedSpeaker) message.Speaker).Name);
                            if (!mSpeakerNames.Any(x => x.SequenceEqual(speakerName)))
                                mSpeakerNames.Add(speakerName.ToArray());

                            binary.SpeakerId = (ushort) mSpeakerNames.FindIndex(x => x.SequenceEqual(speakerName));
                        }
                        break;

                    case MessageScriptDialogueMessageSpeakerType.VariablyNamed:
                        {
                            binary.SpeakerId = (ushort)(0x8000u | ((MessageScriptDialogueMessageVariablyNamedSpeaker)message.Speaker).Index);
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

            binary.LineStartAddresses = new int[message.Lines.Count];

            var textBuffer = new List<byte>();
            {
                int lineStartAddress = 0x1C + (binary.LineCount * 4) + 4;

                for (int i = 0; i < message.Lines.Count; i++)
                {
                    binary.LineStartAddresses[i] = lineStartAddress;

                    var lineBytes = ProcessMessageLine(message.Lines[i]);
                    textBuffer.AddRange(lineBytes);

                    lineStartAddress += lineBytes.Count;
                }

                textBuffer.Add(0);
            }

            binary.TextBuffer = textBuffer.ToArray();
            binary.TextBufferSize = binary.TextBuffer.Length;

            mMessages.Add(new Tuple<MessageScriptBinaryMessageType, object>(MessageScriptBinaryMessageType.Dialogue, binary));
        }

        public void AddMessage(MessageScriptSelectionMessage message)
        {
            if (mMessages == null)
                mMessages = new List<Tuple<MessageScriptBinaryMessageType, object>>();

            MessageScriptBinarySelectionMessage binary;

            binary.Identifier = message.Identifier;
            binary.Field18 = binary.Field1C = binary.Field1E = 0;
            binary.OptionCount = (short)message.Lines.Count;
            binary.OptionStartAddresses = new int[message.Lines.Count];

            var textBuffer = new List<byte>();
            {
                int lineStartAddress = 0x20 + (binary.OptionCount * 4) + 4;
                for (int i = 0; i < message.Lines.Count; i++)
                {
                    binary.OptionStartAddresses[i] = lineStartAddress;

                    var lineBytes = ProcessMessageLine(message.Lines[i]);
                    lineBytes.Add(0); // intentional

                    textBuffer.AddRange(lineBytes);

                    lineStartAddress += lineBytes.Count;
                }

                textBuffer.Add(0); // intentional
            }

            binary.TextBuffer = textBuffer.ToArray();
            binary.TextBufferSize = binary.TextBuffer.Length;

            mMessages.Add(new Tuple<MessageScriptBinaryMessageType, object>(MessageScriptBinaryMessageType.Selection, binary));
        }

        public MessageScriptBinary Build()
        {
            var binary = new MessageScriptBinary
            {
                mFormatVersion = mFormatVersion,
            };

            // note: DONT CHANGE THE ORDER
            BuildHeaderFirstPass(ref binary.mHeader);

            if (mMessages != null)
            {
                BuildMessageHeadersFirstPass(ref binary.mMessageHeaders);

                BuildSpeakerTableHeaderFirstPass(ref binary.mSpeakerTableHeader);

                BuildMessageHeadersFinalPass(ref binary.mMessageHeaders);

                BuildSpeakerTableHeaderSecondPass(ref binary.mSpeakerTableHeader);

                BuildSpeakerTableHeaderFinalPass(ref binary.mSpeakerTableHeader);
            }

            BuildHeaderFinalPass(ref binary.mHeader);

            return binary;
        }

        private List<byte> ProcessMessageLine(MessageScriptLine line)
        {
            List<byte> bytes = new List<byte>();

            foreach (var token in line.Tokens)
            {
                ProcessToken(token, bytes);
            }

            return bytes;
        }

        private void ProcessToken(IMessageScriptLineToken token, List<byte> bytes)
        {
            switch (token.Type)
            {
                case MessageScriptTokenType.Text:
                    ProcessTextToken((MessageScriptTextToken)token, bytes);
                    break;

                case MessageScriptTokenType.Function:
                    ProcessFunctionToken((MessageScriptFunctionToken)token, bytes);
                    break;

                case MessageScriptTokenType.CharacterCode:
                    ProcessCharacterCode((MessageScriptCharacterCodeToken)token, bytes);
                    break;
            }
        }

        private void ProcessTextToken(MessageScriptTextToken token, List<byte> bytes)
        {
            // a text token is a simple 7 bit ascii character
            var textBytes = Encoding.ASCII.GetBytes(token.Text);

            // simple add to the list of bytes
            bytes.AddRange(textBytes);
        }

        private void ProcessFunctionToken(MessageScriptFunctionToken token, List<byte> bytes)
        {
            // AAAA BBBB where A is a signifier value for a function and B is the encoded argument byte size
            byte functionSignifier = (byte)(0xF0 | (((token.Arguments.Count * sizeof(short)) / 2) + 1) & 0x0F);

            // AAAB BBBB where A is the table index and B is the function index
            byte functionId = (byte)(((token.FunctionTableIndex & 0x07) << 5) | token.FunctionIndex & 0x1F);

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

            bytes.Add(functionSignifier);
            bytes.Add(functionId);
            bytes.AddRange(argumentBytes);
        }

        private void ProcessCharacterCode(MessageScriptCharacterCodeToken token, List<byte> bytes)
        {
            bytes.Add((byte)((token.Value & 0xFF00) >> 8));
            bytes.Add((byte)(token.Value & 0xFF));
        }

        private void BuildHeaderFirstPass(ref MessageScriptBinaryHeader header)
        {
            header.FileType = MessageScriptBinaryHeader.FILE_TYPE;
            header.IsCompressed = false;
            header.UserId = mUserId;
            header.Magic = mFormatVersion.HasFlag(MessageScriptBinaryFormatVersion.BigEndian)
                ? MessageScriptBinaryHeader.MAGIC_V1_BE
                : MessageScriptBinaryHeader.MAGIC_V1;
            header.Field0C = 0;
            header.MessageCount = mMessages?.Count ?? 0;
            header.IsRelocated = false;
            header.Field1E = 2;
        }

        private void BuildMessageHeadersFirstPass(ref MessageScriptBinaryMessageHeader[] messageHeaders)
        {
            messageHeaders = new MessageScriptBinaryMessageHeader[mMessages.Count];
            for (int i = 0; i < messageHeaders.Length; i++)
            {
                messageHeaders[i].MessageType = mMessages[i].Item1;
                MoveToNextIntPosition();

                AddAddressLocation();
                MoveToNextIntPosition();
            }
        }

        private void BuildSpeakerTableHeaderFirstPass(ref MessageScriptBinarySpeakerTableHeader speakerHeader)
        {
            AddAddressLocation();
            MoveToNextIntPosition();

            speakerHeader.SpeakerCount = mSpeakerNames.Count;
            MoveToNextIntPosition();

            speakerHeader.Field08 = 0;
            MoveToNextIntPosition();

            speakerHeader.Field0C = 0;
            MoveToNextIntPosition();
        }

        private void BuildMessageHeadersFinalPass(ref MessageScriptBinaryMessageHeader[] messageHeaders)
        {
            for (int i = 0; i < messageHeaders.Length; i++)
            {
                messageHeaders[i].Message.Address = GetAlignedAddress();
                messageHeaders[i].Message.Value = UpdateMessageAddressBase(mMessages[i].Item2);
            }
        }

        private void BuildSpeakerTableHeaderSecondPass(ref MessageScriptBinarySpeakerTableHeader speakerTableHeader)
        {
            speakerTableHeader.SpeakerNameArray.Address = GetAlignedAddress();
            for (int i = 0; i < speakerTableHeader.SpeakerCount; i++)
            {
                AddAddressLocation();
                MoveToNextIntPosition();
            }
        }

        private void BuildSpeakerTableHeaderFinalPass(ref MessageScriptBinarySpeakerTableHeader speakerTableHeader)
        {
            speakerTableHeader.SpeakerNameArray.Value = new AddressValuePair<List<byte>>[speakerTableHeader.SpeakerCount];
            for (int i = 0; i < speakerTableHeader.SpeakerNameArray.Value.Length; i++)
            {
                speakerTableHeader.SpeakerNameArray.Value[i].Address = GetAddress();
                speakerTableHeader.SpeakerNameArray.Value[i].Value = mSpeakerNames[i].ToList();

                // todo: maybe the speakername should include the trailing 0
                MoveToNextPositionByOffset(mSpeakerNames[i].Length + 1);
            }
        }

        private void BuildHeaderFinalPass(ref MessageScriptBinaryHeader header)
        {
            header.RelocationTable.Address = GetAlignedAddress() + MessageScriptBinaryHeader.SIZE;
            header.RelocationTable.Value =
                RelocationTableEncoding.Encode(mAddressLocations, MessageScriptBinaryHeader.SIZE);
            header.RelocationTableSize = header.RelocationTable.Value.Length;
            mPosition += header.RelocationTableSize;

            header.FileSize = mPosition;
        }

        private object UpdateMessageAddressBase(object message)
        {
            int messageAddress = GetAddress();

            switch (message)
            {
                case MessageScriptBinaryDialogueMessage dialogue:
                {
                    mPosition += 0x1C;

                    for (int i = 0; i < dialogue.LineStartAddresses.Length; i++)
                    {
                        AddAddressLocation();
                        dialogue.LineStartAddresses[i] += messageAddress;
                        mPosition += 4;
                    }

                    mPosition += 4 + dialogue.TextBufferSize;
                }
                    break;

                case MessageScriptBinarySelectionMessage selection:
                {
                    mPosition += 0x20;

                    for (int i = 0; i < selection.OptionStartAddresses.Length; i++)
                    {
                        AddAddressLocation();
                        selection.OptionStartAddresses[i] += messageAddress;
                        mPosition += 4;
                    }

                    mPosition += 4 + selection.TextBufferSize;
                }
                    break;
            }

            return message;
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
            mPosition = (mPosition + 3) & ~3;
        }

        private int GetAddress()
        {
            return mPosition - MessageScriptBinaryHeader.SIZE;
        }

        private int GetAlignedAddress()
        {
            AlignPosition();
            return GetAddress();
        }
    }
}
