using System;
using System.IO;
using System.Text;
using TGELib.IO;

namespace AtlusScriptLib
{
    public sealed class MessageScriptBinaryWriter : IDisposable
    {
        private bool mDisposed;
        private readonly long mPositionBase;
        private readonly EndianBinaryWriter mWriter;

        public MessageScriptBinaryWriter(Stream stream, MessageScriptBinaryFormatVersion version, bool leaveOpen = false)
        {
            mPositionBase = stream.Position;
            mWriter = new EndianBinaryWriter(stream, Encoding.ASCII, leaveOpen, version.HasFlag(MessageScriptBinaryFormatVersion.BigEndian) ? Endianness.BigEndian : Endianness.LittleEndian);
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
            WriteMessageHeaders(binary.mMessageHeaders);
            WriteSpeakerHeader(ref binary.mSpeakerTableHeader);
            WriteMessages(binary.mMessageHeaders);
            WriteSpeakerNameOffsets(ref binary.mSpeakerTableHeader);
            WriteSpeakerNames(ref binary.mSpeakerTableHeader);
            WriteRelocationTable(ref binary.mHeader.RelocationTable);
        }

        private void WriteHeader(ref MessageScriptBinaryHeader header)
        {
            mWriter.Write(header.FileType);
            mWriter.Write(header.IsCompressed ? (byte)1 : (byte)0);
            mWriter.Write(header.UserId);
            mWriter.Write(header.FileSize);
            mWriter.Write(header.Magic);
            mWriter.Write(header.Field0C);
            mWriter.Write(header.RelocationTable.Address);
            mWriter.Write(header.RelocationTableSize);
            mWriter.Write(header.MessageCount);
            mWriter.Write(header.IsRelocated ? (short)1 : (short)0);
            mWriter.Write(header.Field1E);
        }

        private void WriteMessageHeaders(MessageScriptBinaryMessageHeader[] messageHeaders)
        {
            foreach (var messageHeader in messageHeaders)
            {
                mWriter.Write((int)messageHeader.MessageType);
                mWriter.Write(messageHeader.Message.Address);
            }
        }

        private void WriteSpeakerHeader(ref MessageScriptBinarySpeakerTableHeader header)
        {
            mWriter.Write(header.SpeakerNameArray.Address);
            mWriter.Write(header.SpeakerCount);
            mWriter.Write(header.Field08);
            mWriter.Write(header.Field0C);
        }

        private void WriteMessages(MessageScriptBinaryMessageHeader[] messageHeaders)
        {
            foreach (var messageHeader in messageHeaders)
            {
                mWriter.SeekBegin(mPositionBase + MessageScriptBinaryHeader.SIZE + messageHeader.Message.Address);

                switch (messageHeader.MessageType)
                {
                    case MessageScriptBinaryMessageType.Dialogue:
                        WriteDialogueMessage((MessageScriptBinaryDialogueMessage) messageHeader.Message.Value);
                        break;

                    case MessageScriptBinaryMessageType.Selection:
                        WriteSelectionMessage((MessageScriptBinarySelectionMessage) messageHeader.Message.Value);
                        break;

                    default:
                        throw new NotImplementedException( messageHeader.MessageType.ToString() );
                }
            }
        }

        private void WriteDialogueMessage(MessageScriptBinaryDialogueMessage dialogue)
        {
            mWriter.Write(dialogue.Identifier, StringBinaryFormat.FixedLength, MessageScriptBinaryDialogueMessage.IDENTIFIER_LENGTH);
            mWriter.Write(dialogue.LineCount);
            mWriter.Write(dialogue.SpeakerId);

            if (dialogue.LineCount > 0)
            {
                mWriter.Write(dialogue.LineStartAddresses);
                mWriter.Write(dialogue.TextBufferSize);
                mWriter.Write(dialogue.TextBuffer);
            }
        }

        private void WriteSelectionMessage(MessageScriptBinarySelectionMessage selection)
        {
            mWriter.Write(selection.Identifier, StringBinaryFormat.FixedLength, MessageScriptBinarySelectionMessage.IDENTIFIER_LENGTH);
            mWriter.Write(selection.Field18);
            mWriter.Write(selection.OptionCount);
            mWriter.Write(selection.Field1C);
            mWriter.Write(selection.Field1E);
            mWriter.Write(selection.OptionStartAddresses);
            mWriter.Write(selection.TextBufferSize);
            mWriter.Write(selection.TextBuffer);
        }

        private void WriteSpeakerNameOffsets(ref MessageScriptBinarySpeakerTableHeader header)
        {
            mWriter.SeekBegin(mPositionBase + MessageScriptBinaryHeader.SIZE + header.SpeakerNameArray.Address);
            foreach (var speakerName in header.SpeakerNameArray.Value)
                mWriter.Write(speakerName.Address);
        }

        private void WriteSpeakerNames(ref MessageScriptBinarySpeakerTableHeader header)
        {
            foreach (var speakerName in header.SpeakerNameArray.Value)
            {
                mWriter.SeekBegin(mPositionBase + MessageScriptBinaryHeader.SIZE + speakerName.Address);
                mWriter.Write(speakerName.Value.ToArray());
                mWriter.Write((byte)0);
            }
        }

        private void WriteRelocationTable(ref AddressValuePair<byte[]> relocationTable)
        {
            mWriter.SeekBegin(mPositionBase + relocationTable.Address);
            mWriter.Write(relocationTable.Value);
        }
    }
}