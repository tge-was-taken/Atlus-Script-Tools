using System.Collections.ObjectModel;
using System.IO;

namespace AtlusScriptLib
{
    // Todo: ensure immutability
    public sealed class FlowScriptBinary
    {
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
            get { return new ReadOnlyCollection<FlowScriptBinarySectionHeader>(mSectionHeaders); }
        }

        public ReadOnlyCollection<FlowScriptBinaryLabel> ProcedureLabelSection
        {
            get { return new ReadOnlyCollection<FlowScriptBinaryLabel>(mProcedureLabelSection); }
        }

        public ReadOnlyCollection<FlowScriptBinaryLabel> JumpLabelSection
        {
            get { return new ReadOnlyCollection<FlowScriptBinaryLabel>(mJumpLabelSection); }
        }

        public ReadOnlyCollection<FlowScriptBinaryInstruction> TextSection
        {
            get { return new ReadOnlyCollection<FlowScriptBinaryInstruction>(mTextSection); }
        }

        public ReadOnlyCollection<byte> MessageScriptSection
        {
            get { return new ReadOnlyCollection<byte>(mMessageScriptSection); }
        }

        public ReadOnlyCollection<byte> StringSection
        {
            get { return new ReadOnlyCollection<byte>(mStringSection); }
        }

        public FlowScriptBinaryFormatVersion FormatVersion
        {
            get { return mFormatVersion; }
        }

        // this constructor is internal because it is used by the builder
        internal FlowScriptBinary()
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
