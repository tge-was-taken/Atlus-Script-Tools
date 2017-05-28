using AtlusScriptLib.Common.IO;
using System;
using System.IO;

namespace AtlusScriptLib
{
    public sealed class MessageScriptBinaryWriter : IDisposable
    {
        private bool mDisposed;
        private long mPositionBase;
        private EndianBinaryWriter mWriter;
        private MessageScriptBinaryFormatVersion mFormatVersion;

        public MessageScriptBinaryWriter(Stream stream, MessageScriptBinaryFormatVersion version)
        {
            mPositionBase = stream.Position;
            mWriter = new EndianBinaryWriter(stream, version.HasFlag(MessageScriptBinaryFormatVersion.BigEndian) ? Endianness.BigEndian : Endianness.LittleEndian);
            mFormatVersion = version;
        }

        public void Dispose()
        {
            if (mDisposed)
                return;

            ((IDisposable)mWriter).Dispose();

            mDisposed = true;
        }

        internal void WriteBinary(MessageScriptBinary messageScriptBinary)
        {
            throw new NotImplementedException();
        }
    }
}