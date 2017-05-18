using System.Collections.ObjectModel;
using System.IO;

namespace AtlusScriptLib
{
    public class MessageScriptBinary
    {
        public static MessageScriptBinary FromFile(string path)
        {
            return FromFile(path, MessageScriptBinaryFormatVersion.Unknown);
        }

        public static MessageScriptBinary FromFile(string path, MessageScriptBinaryFormatVersion version)
        {
            using (var fileStream = File.OpenRead(path))
                return FromStream(fileStream, version);
        }

        public static MessageScriptBinary FromStream(Stream stream)
        {
            return FromStream(stream, MessageScriptBinaryFormatVersion.Unknown);
        }

        public static MessageScriptBinary FromStream(Stream stream, MessageScriptBinaryFormatVersion version)
        {
            using (var reader = new MessageScriptBinaryReader(stream, version))
            {
                return reader.ReadBinary();
            }
        }

        // these fields are internal because they are used by the builder, reader & writer
        internal MessageScriptBinaryHeader mHeader;
        internal MessageScriptBinaryMessageHeader[] mMessageHeaders;
        internal MessageScriptBinarySpeakerTableHeader mSpeakerTableHeader;
        internal MessageScriptBinaryFormatVersion mFormatVersion;

        public MessageScriptBinaryHeader Header
        {
            get { return mHeader; }
        }

        public ReadOnlyCollection<MessageScriptBinaryMessageHeader> MessageHeaders
        {
            get { return new ReadOnlyCollection<MessageScriptBinaryMessageHeader>(mMessageHeaders); }
        }

        public MessageScriptBinarySpeakerTableHeader SpeakerTableHeader
        {
            get { return mSpeakerTableHeader; }
        }

        public MessageScriptBinaryFormatVersion FormatVersion
        {
            get { return mFormatVersion; }
        }

        // this constructor is internal because it is used by the builder, reader & writer
        internal MessageScriptBinary()
        {
        }

        public void ToFile(string path)
        {
            ToStream(File.Create(path));
        }

        public Stream ToStream()
        {
            var stream = new MemoryStream();
            ToStream(stream);
            return stream;
        }

        public void ToStream(Stream stream)
        {
            using (var writer = new MessageScriptBinaryWriter(stream, mFormatVersion))
            {
                writer.WriteBinary(this);
            }
        }
    }
}
