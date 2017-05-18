using AtlusScriptLib.Common.IO;
using System;
using System.IO;

namespace AtlusScriptLib
{
    public class FlowScriptBinaryWriter : IDisposable
    {
        private long mPositionBase;
        private EndianBinaryWriter mWriter;
        private FlowScriptBinaryFormatVersion mVersion;
        private bool mDisposed;
        private FlowScriptBinary mBinary;
        private FlowScriptBinaryHeader mHeader;
        

        public FlowScriptBinaryWriter(Stream stream, FlowScriptBinaryFormatVersion version)
        {
            mPositionBase = stream.Position;
            mWriter = new EndianBinaryWriter(stream, version.HasFlag(FlowScriptBinaryFormatVersion.BE) ? Endianness.BigEndian : Endianness.LittleEndian);
            mVersion = version;
        }

        public void WriteHeader(ref FlowScriptBinaryHeader header)
        {
            mWriter.Write(ref header);
        }

        public void WriteSectionHeaders(FlowScriptBinarySectionHeader[] sectionHeaders)
        {
            mWriter.Write(sectionHeaders);
        }

        public void WriteLabelSection(ref FlowScriptBinarySectionHeader sectionHeader, FlowScriptBinaryLabel[] labels)
        {
            mWriter.SeekBegin(mPositionBase + sectionHeader.FirstElementAddress);
            mWriter.Write(labels);
        }

        public void WriteTextSection(ref FlowScriptBinarySectionHeader sectionHeader, FlowScriptBinaryInstruction[] instructions)
        {
            mWriter.SeekBegin(mPositionBase + sectionHeader.FirstElementAddress);
            mWriter.Write(instructions);
        }

        public void WriteMessageScriptSection(ref FlowScriptBinarySectionHeader sectionHeader, byte[] messageScript)
        {
            mWriter.SeekBegin(mPositionBase + sectionHeader.FirstElementAddress);
            mWriter.Write(messageScript);
        }

        public void WriteStringSection(ref FlowScriptBinarySectionHeader sectionHeader, byte[] stringSection)
        {
            mWriter.SeekBegin(mPositionBase + sectionHeader.FirstElementAddress);
            mWriter.Write(stringSection);
        }

        public void Dispose()
        {
            if (mDisposed)
                return;

            // Dispose the writer, and thus the stream as well
            ((IDisposable)mWriter).Dispose();

            mDisposed = true;
        }
    }
}
