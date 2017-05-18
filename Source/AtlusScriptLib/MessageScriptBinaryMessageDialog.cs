using AtlusScriptLib.Common.IO;

namespace AtlusScriptLib.MessageScript
{
    public class MessageScriptBinaryMessageDialog : MessageScriptBinaryMessage
    {
        private MessageScriptBinaryMessageDialogHeader mHeader;
        private int[] mDialogOffsets;
        private int mDataSize;
        private byte[] mData;

        public override MessageScriptBinaryMessageType Type => MessageScriptBinaryMessageType.MessageDialog;

        internal static MessageScriptBinaryMessageDialog Read(EndianBinaryReader reader)
        {
            MessageScriptBinaryMessageDialog instance = new MessageScriptBinaryMessageDialog();

            instance.mHeader = reader.ReadStruct<MessageScriptBinaryMessageDialogHeader>();
            instance.mDialogOffsets = reader.ReadInt32s(instance.mHeader.DialogCount);
            instance.mDataSize = reader.ReadInt32();
            instance.mData = reader.ReadBytes(instance.mDataSize);

            return instance;
        }
    }
}
