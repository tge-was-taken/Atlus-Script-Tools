using System.IO;

namespace AtlusScriptLib
{
    public sealed class FlowScriptBinary
    {
        private FlowScriptBinaryHeader mHeader;
        private FlowScriptBinarySectionHeader[] mSectionHeaders;
        private FlowScriptBinaryLabel[] mProcedureLabelSection;
        private FlowScriptBinaryLabel[] mJumpLabelSection;
        private FlowScriptBinaryInstruction[] mTextSection;
        private byte[] mMessageScriptSection;
        private byte[] mStringSection;
        private FlowScriptBinaryFormatVersion mFormatVersion;

        public FlowScriptBinaryHeader Header
        {
            get { return mHeader; }
        }

        public FlowScriptBinarySectionHeader[] SectionHeaders
        {
            get { return mSectionHeaders; }
        }

        public FlowScriptBinaryLabel[] ProcedureLabelSection
        {
            get { return mProcedureLabelSection; }
        }

        public FlowScriptBinaryLabel[] JumpLabelSection
        {
            get { return mJumpLabelSection; }
        }

        public FlowScriptBinaryInstruction[] TextSection
        {
            get { return mTextSection; }
        }

        public byte[] MessageScriptSection
        {
            get { return mMessageScriptSection; }
        }

        public byte[] StringSection
        {
            get { return mStringSection; }
        }

        public FlowScriptBinaryFormatVersion FormatVersion
        {
            get { return mFormatVersion; }
        }

        private FlowScriptBinary()
        {          
        }

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
            FlowScriptBinary instance = new FlowScriptBinary();

            using (var reader = new FlowScriptBinaryReader(stream, version))
            {
                instance.mHeader = reader.ReadHeader();
                instance.mSectionHeaders = reader.ReadSectionHeaders(ref instance.mHeader);

                for (int i = 0; i < instance.mSectionHeaders.Length; i++)
                {
                    ref var sectionHeader = ref instance.mSectionHeaders[i];

                    switch (sectionHeader.SectionType)
                    {
                        case FlowScriptBinarySectionType.ProcedureLabelSection:
                            instance.mProcedureLabelSection = reader.ReadLabelSection(ref sectionHeader);
                            break;

                        case FlowScriptBinarySectionType.JumpLabelSection:
                            instance.mJumpLabelSection = reader.ReadLabelSection(ref sectionHeader);
                            break;

                        case FlowScriptBinarySectionType.TextSection:
                            instance.mTextSection = reader.ReadTextSection(ref sectionHeader);
                            break;

                        case FlowScriptBinarySectionType.MessageScriptSection:
                            instance.mMessageScriptSection = reader.ReadMessageScriptSection(ref sectionHeader);
                            break;

                        case FlowScriptBinarySectionType.StringSection:
                            instance.mStringSection = reader.ReadStringSection(ref sectionHeader);
                            break;

                        default:
                            throw new InvalidDataException("Unknown section type");
                    }
                }

                instance.mFormatVersion = reader.GetDetectedFormatVersion();
            }

            return instance;
        }
    }
}
