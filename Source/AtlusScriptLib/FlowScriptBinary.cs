using System;
using System.Collections.ObjectModel;
using System.IO;

namespace AtlusScriptLib
{
    // Todo: ensure immutability
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

        private FlowScriptBinary()
        {          
        }

        public void InvokeLinker()
        {
            var linker = new Linker(this);
            linker.Link();
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

        private class Linker
        {
            private FlowScriptBinary mBinary;

            public Linker(FlowScriptBinary binary)
            {
                mBinary = binary;
            }

            public void Link()
            {
                // Header
                mBinary.mHeader.FileSize = CalculateHeaderFileSize();

                // Section headers
                int nextSectionAddress = FlowScriptBinaryHeader.SIZE + (mBinary.mSectionHeaders.Length * FlowScriptBinarySectionHeader.SIZE);
                for (int i = 0; i < mBinary.mSectionHeaders.Length; i++)
                {
                    ref var sectionheader = ref mBinary.mSectionHeaders[i];

                    sectionheader.FirstElementAddress = nextSectionAddress;
                    nextSectionAddress += (sectionheader.ElementCount * sectionheader.ElementSize);
                }
            }

            private int CalculateHeaderFileSize()
            {
                int size = FlowScriptBinaryHeader.SIZE;
                int labelSize = mBinary.mFormatVersion.HasFlag(FlowScriptBinaryFormatVersion.V1) ? FlowScriptBinaryLabel.SIZE_V1 :
                                mBinary.mFormatVersion.HasFlag(FlowScriptBinaryFormatVersion.V2) ? FlowScriptBinaryLabel.SIZE_V2 :
                                mBinary.mFormatVersion.HasFlag(FlowScriptBinaryFormatVersion.V3) ? FlowScriptBinaryLabel.SIZE_V3 :
                                throw new Exception("Invalid format version");

                if (mBinary.ProcedureLabelSection != null)
                    size += (FlowScriptBinarySectionHeader.SIZE + (mBinary.ProcedureLabelSection.Count * labelSize));

                if (mBinary.JumpLabelSection != null)
                    size += (FlowScriptBinarySectionHeader.SIZE + (mBinary.JumpLabelSection.Count * labelSize));

                if (mBinary.TextSection != null)
                    size += mBinary.TextSection.Count * FlowScriptBinaryInstruction.SIZE;

                if (mBinary.MessageScriptSection != null)
                    size += mBinary.MessageScriptSection.Count;

                if (mBinary.StringSection != null)
                    size += mBinary.StringSection.Count;

                return size;
            }
        }
    }
}
