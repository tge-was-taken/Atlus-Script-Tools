using System;
using System.Collections.ObjectModel;
using System.IO;

namespace AtlusScriptLib
{
    // Todo: ensure immutability
    public sealed class FlowScriptBinary
    {
        public static FlowScriptBinary FromFile(string path)
        {
            return FromFile(path, FlowScriptBinaryFormatVersion.Unknown);
        }

        public static FlowScriptBinary FromFile(string path, FlowScriptBinaryFormatVersion version)
        {
            using (var fileStream = File.OpenRead(path))
                return FromStream(fileStream, version);
        }

        public static FlowScriptBinary FromStream(Stream stream)
        {
            return FromStream(stream, FlowScriptBinaryFormatVersion.Unknown);
        }

        public static FlowScriptBinary FromStream(Stream stream, FlowScriptBinaryFormatVersion version)
        {
            using (var reader = new FlowScriptBinaryReader(stream, version))
            {
                return reader.ReadBinary();
            }
        }

        // these fields are internal because they are used by the builder
        internal FlowScriptBinaryHeader mHeader;
        internal FlowScriptBinarySectionHeader[] mSectionHeaders;
        internal FlowScriptBinaryLabel[] mProcedureLabelSection;
        internal FlowScriptBinaryLabel[] mJumpLabelSection;
        internal FlowScriptBinaryInstruction[] mTextSection;
        internal byte[] mMessageScriptSection;
        internal byte[] mStringSection;
        internal FlowScriptBinaryFormatVersion mFormatVersion;

        public FlowScriptBinaryHeader Header
        {
            get { return mHeader; }
        }

        public ReadOnlyCollection<FlowScriptBinarySectionHeader> SectionHeaders
        {
            get
            {
                if (mSectionHeaders == null)
                    return null;
                else
                    return new ReadOnlyCollection<FlowScriptBinarySectionHeader>(mSectionHeaders);
            }
        }

        public ReadOnlyCollection<FlowScriptBinaryLabel> ProcedureLabelSection
        {
            get
            {
                if (mProcedureLabelSection == null)
                    return null;
                else
                    return new ReadOnlyCollection<FlowScriptBinaryLabel>(mProcedureLabelSection);
            }
        }

        public ReadOnlyCollection<FlowScriptBinaryLabel> JumpLabelSection
        {
            get
            {
                if (mJumpLabelSection == null)
                    return null;
                else
                    return new ReadOnlyCollection<FlowScriptBinaryLabel>(mJumpLabelSection);
            }
        }

        public ReadOnlyCollection<FlowScriptBinaryInstruction> TextSection
        {
            get
            {
                if (mTextSection == null)
                    return null;
                else
                    return new ReadOnlyCollection<FlowScriptBinaryInstruction>(mTextSection);
            }
        }

        public ReadOnlyCollection<byte> MessageScriptSection
        {
            get
            {
                if (mMessageScriptSection == null)
                    return null;
                else
                    return new ReadOnlyCollection<byte>(mMessageScriptSection);
            }
        }

        public ReadOnlyCollection<byte> StringSection
        {
            get
            {
                if (mStringSection == null)
                    return null;
                else
                    return new ReadOnlyCollection<byte>(mStringSection);
            }
        }

        public FlowScriptBinaryFormatVersion FormatVersion
        {
            get { return mFormatVersion; }
        }

        // this constructor is internal because it is used by the builder
        internal FlowScriptBinary()
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
            using (var writer = new FlowScriptBinaryWriter(stream, mFormatVersion))
            {
                writer.WriteBinary(this);
            }
        }
    }
}
