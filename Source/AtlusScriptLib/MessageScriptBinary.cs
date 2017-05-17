using AtlusScriptLib.Common.IO;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;

namespace AtlusScriptLib.MessageScript
{
    public class MessageScriptBinary
    {
        private MessageScriptBinaryHeader mHeader;
        private byte[] mRelocationTable;
        private MessageScriptBinaryMessageHeader[] mMessageHeaders;
        private MessageScriptBinarySpeakerTableHeader mSpeakerTableHeader;
        private int[] mSpeakerNameOffsets;
        private string[] mSpeakerNames;
        private MessageScriptBinaryMessage[] mMessages;

        public MessageScriptBinaryHeader Header
        {
            get { return mHeader; }
        }

        public ReadOnlyCollection<byte> RelocationTable
        {
            get { return new ReadOnlyCollection<byte>(mRelocationTable); }
        }

        public ReadOnlyCollection<MessageScriptBinaryMessageHeader> MessageHeaders
        {
            get { return new ReadOnlyCollection<MessageScriptBinaryMessageHeader>(mMessageHeaders); }
        }

        public MessageScriptBinarySpeakerTableHeader SpeakerTableHeader
        {
            get { return mSpeakerTableHeader; }
        }

        public ReadOnlyCollection<MessageScriptBinaryMessage> Messages
        {
            get { return new ReadOnlyCollection<MessageScriptBinaryMessage>(mMessages); }
        }

        public static void LoadFromStream(Stream stream)
        {
            MessageScriptBinary instance = new MessageScriptBinary();
            long positionBase = stream.Position + MessageScriptBinaryHeader.SIZE;

            using (var reader = new EndianBinaryReader(stream, Endianness.LittleEndian))
            {
                instance.mHeader = reader.ReadStruct<MessageScriptBinaryHeader>();
                if (instance.mHeader.Magic.SequenceEqual(MessageScriptBinaryHeader.MAGIC_BE))
                {
                    reader.Endianness = Endianness.BigEndian;
                    instance.mHeader = EndiannessHelper.SwapEndianness(instance.mHeader);
                }

                // Save position for later
                reader.PushPosition();

                // Read relocation table
                reader.SeekBegin(positionBase + instance.mHeader.RelocationTableOffset);
                instance.mRelocationTable = reader.ReadBytes(instance.mHeader.RelocationTableSize);

                // Go back and read message headers
                reader.SeekBegin(reader.PopPosition());
                instance.mMessageHeaders = reader.ReadStruct<MessageScriptBinaryMessageHeader>(instance.mHeader.MessageCount);

                // Read speaker table header
                instance.mSpeakerTableHeader = reader.ReadStruct<MessageScriptBinarySpeakerTableHeader>();

                // Read speaker name table
                reader.SeekBegin(positionBase + instance.mSpeakerTableHeader.SpeakerNameTableOffset);
                instance.mSpeakerNameOffsets = reader.ReadInt32s(instance.mSpeakerTableHeader.SpeakerCount);
                instance.mSpeakerNames = new string[instance.mSpeakerTableHeader.SpeakerCount];

                for (int i = 0; i < instance.mSpeakerTableHeader.SpeakerCount; i++)
                {
                    reader.SeekBegin(positionBase + instance.mSpeakerNameOffsets[i]);
                    instance.mSpeakerNames[i] = reader.ReadString(StringBinaryFormat.NullTerminated);
                }

                // Read messages
                instance.mMessages = new MessageScriptBinaryMessage[instance.mHeader.MessageCount];
                for (int i = 0; i < instance.mMessages.Length; i++)
                {
                    reader.SeekBegin(positionBase + instance.mMessageHeaders[i].Offset);

                    if (instance.mMessageHeaders[i].Type == 0)
                    {
                        instance.mMessages[i] = MessageScriptBinaryMessageDialog.Read(reader);
                    }
                    else if (instance.mMessageHeaders[i].Type == 1)
                    {

                    }
                    else
                    {

                    }
                }
            }
        }
    }
}
