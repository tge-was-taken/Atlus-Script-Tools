using AtlusScriptLib.Common.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.MessageScript
{
    internal class MessageScriptLoader : IDisposable
    {
        /* IO */
        private Stream mStream;
        private long mPositionBase;
        private EndianBinaryReader mReader;  

        /* Internal structures */
        private MessageScriptBinaryHeader mHeader;
        private MessageScriptBinarySpeakerTableHeader mSpeakerTableHeader;

        public MessageScript LoadFromStream(Stream stream)
        {
            mStream = stream;
            mPositionBase = mStream.Position;
            mReader = new EndianBinaryReader(stream, Endianness.LittleEndian);
            return Load();
        }

        private MessageScript Load()
        {
            return null;
        }

        private void ReadHeader()
        {
            mHeader = mReader.ReadStruct<MessageScriptBinaryHeader>();

        }

        public void Dispose()
        {
            ((IDisposable)mStream).Dispose();
            ((IDisposable)mReader).Dispose();
        }
    }
}
