using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AtlusScriptLib
{
    public class FlowScriptBinaryBuilder
    {
        // required
        private FlowScriptBinaryFormatVersion mFormatVersion;

        // optional
        private short mUserId;
        private IList<FlowScriptBinaryLabel> mProcedureLabelSection;
        private IList<FlowScriptBinaryLabel> mJumpLabelSection;
        private IList<FlowScriptBinaryInstruction> mTextSection;
        private IList<byte> mMessageScriptSection;
        private IList<byte> mStringSection;
        
        public FlowScriptBinaryBuilder(FlowScriptBinaryFormatVersion version)
        {
            mFormatVersion = version;
        }

        public void SetUserId(short value)
        {
            mUserId = value;
        }

        public void SetProcedureLabelSection(IList<FlowScriptBinaryLabel> procedureLabelSection)
        {
            mProcedureLabelSection = procedureLabelSection;
        }

        public void AddProcedureLabel(FlowScriptBinaryLabel label)
        {
            if (mProcedureLabelSection == null)
                mProcedureLabelSection = new List<FlowScriptBinaryLabel>();

            mProcedureLabelSection.Add(label);
        }

        public void SetJumpLabelSection(IList<FlowScriptBinaryLabel> jumpLabelSection)
        {
            mJumpLabelSection = jumpLabelSection;
        }

        public void AddJumpLabel(FlowScriptBinaryLabel label)
        {
            if (mJumpLabelSection == null)
                mJumpLabelSection = new List<FlowScriptBinaryLabel>();

            mJumpLabelSection.Add(label);
        }

        public void SetTextSection(IList<FlowScriptBinaryInstruction> textSection)
        {
            mTextSection = textSection;
        }

        public void AddInstruction(FlowScriptBinaryInstruction instruction)
        {
            if (mTextSection == null)
                mTextSection = new List<FlowScriptBinaryInstruction>();

            mTextSection.Add(instruction);
        }

        public void SetMessageScriptSection(IList<byte> messageScriptSection)
        {
            mMessageScriptSection = messageScriptSection;
        }

        public void SetStringSection(IList<byte> stringSection)
        {
            mStringSection = stringSection;
        }

        public void AddString(string value)
        {
            var bytes = Encoding.GetEncoding(932).GetBytes(value);

            for (int i = 0; i < bytes.Length; i++)
                mStringSection.Add(bytes[i]);

            mStringSection.Add(0);
        }

        public FlowScriptBinary Build()
        {
            var binary = new FlowScriptBinary();

            // Build the headers 
            binary.mHeader = BuildHeader();
            binary.mSectionHeaders = BuildSectionHeaders();

            // Copy the section data to the binary
            if (mProcedureLabelSection != null)
                binary.mProcedureLabelSection = mProcedureLabelSection.ToArray();

            if (mJumpLabelSection != null)
                binary.mJumpLabelSection = mJumpLabelSection.ToArray();

            if (mTextSection != null)
                binary.mTextSection = mTextSection.ToArray();

            if (mMessageScriptSection != null)
                binary.mMessageScriptSection = mMessageScriptSection.ToArray();

            if (mStringSection != null)
                binary.mStringSection = mStringSection.ToArray();

            // Set format
            binary.mFormatVersion = mFormatVersion;

            return binary;
        }

        private FlowScriptBinaryHeader BuildHeader()
        {
            return new FlowScriptBinaryHeader()
            {
                FileType                = FlowScriptBinaryHeader.FILE_TYPE,
                Compressed              = false,
                UserId                  = mUserId,
                FileSize                = CalculateFileSize(),
                Magic                   = FlowScriptBinaryHeader.MAGIC,
                Field0C                 = 0,
                SectionCount            = CalculateSectionCount(),
                LocalIntVariableCount   = CalculateLocalIntVariableCount(),
                LocalFloatVariableCount = CalculateLocalFloatVariableCount(),
                Endianness              = 0,
                Field1A                 = 0,
                Padding                 = 0
            };
        }

        private FlowScriptBinarySectionHeader[] BuildSectionHeaders()
        {
            var sectionHeaders = new FlowScriptBinarySectionHeader[CalculateSectionCount()];

            int nextFirstElementAddress = FlowScriptBinaryHeader.SIZE + (sectionHeaders.Length * FlowScriptBinarySectionHeader.SIZE);
            int currentSectionHeaderIndex = 0;

            if (mProcedureLabelSection != null)
            {
                var sectionHeader = new FlowScriptBinarySectionHeader()
                {
                    SectionType = FlowScriptBinarySectionType.ProcedureLabelSection,
                    ElementSize = CalculateLabelSize(),
                    ElementCount = mProcedureLabelSection.Count,
                    FirstElementAddress = nextFirstElementAddress
                };

                nextFirstElementAddress += (sectionHeader.ElementCount * sectionHeader.ElementSize);
                sectionHeaders[currentSectionHeaderIndex++] = sectionHeader;
            }

            if (mJumpLabelSection != null)
            {
                var sectionHeader = new FlowScriptBinarySectionHeader()
                {
                    SectionType = FlowScriptBinarySectionType.JumpLabelSection,
                    ElementSize = CalculateLabelSize(),
                    ElementCount = mJumpLabelSection.Count,
                    FirstElementAddress = nextFirstElementAddress
                };

                nextFirstElementAddress += (sectionHeader.ElementCount * sectionHeader.ElementSize);
                sectionHeaders[currentSectionHeaderIndex++] = sectionHeader;
            }

            if (mTextSection != null)
            {
                var sectionHeader = new FlowScriptBinarySectionHeader()
                {
                    SectionType = FlowScriptBinarySectionType.TextSection,
                    ElementSize = FlowScriptBinaryInstruction.SIZE,
                    ElementCount = mTextSection.Count,
                    FirstElementAddress = nextFirstElementAddress
                };

                nextFirstElementAddress += (sectionHeader.ElementCount * sectionHeader.ElementSize);
                sectionHeaders[currentSectionHeaderIndex++] = sectionHeader;
            }

            if (mMessageScriptSection != null)
            {
                var sectionHeader = new FlowScriptBinarySectionHeader()
                {
                    SectionType = FlowScriptBinarySectionType.MessageScriptSection,
                    ElementSize = sizeof(byte),
                    ElementCount = mMessageScriptSection.Count,
                    FirstElementAddress = nextFirstElementAddress
                };

                nextFirstElementAddress += (sectionHeader.ElementCount * sectionHeader.ElementSize);
                sectionHeaders[currentSectionHeaderIndex++] = sectionHeader;
            }

            if (mStringSection != null)
            {
                var sectionHeader = new FlowScriptBinarySectionHeader()
                {
                    SectionType = FlowScriptBinarySectionType.StringSection,
                    ElementSize = sizeof(byte),
                    ElementCount = mStringSection.Count,
                    FirstElementAddress = nextFirstElementAddress
                };

                sectionHeaders[currentSectionHeaderIndex] = sectionHeader;
            }

            return sectionHeaders;
        }

        private int CalculateLabelSize()
        {
            return mFormatVersion.HasFlag(FlowScriptBinaryFormatVersion.V1) ? FlowScriptBinaryLabel.SIZE_V1 :
                   mFormatVersion.HasFlag(FlowScriptBinaryFormatVersion.V2) ? FlowScriptBinaryLabel.SIZE_V2 :
                   mFormatVersion.HasFlag(FlowScriptBinaryFormatVersion.V3) ? FlowScriptBinaryLabel.SIZE_V3 :
                   throw new Exception("Invalid format version");
        }

        private int CalculateFileSize()
        {
            int size = FlowScriptBinaryHeader.SIZE;
            int labelSize = CalculateLabelSize();

            if (mProcedureLabelSection != null)
                size += (FlowScriptBinarySectionHeader.SIZE + (mProcedureLabelSection.Count * labelSize));

            if (mJumpLabelSection != null)
                size += (FlowScriptBinarySectionHeader.SIZE + (mJumpLabelSection.Count * labelSize));

            if (mTextSection != null)
                size += (FlowScriptBinarySectionHeader.SIZE + (mTextSection.Count * FlowScriptBinaryInstruction.SIZE));

            if (mMessageScriptSection != null)
                size += (FlowScriptBinarySectionHeader.SIZE + (mMessageScriptSection.Count * sizeof(byte)));

            if (mStringSection != null)
                size += (FlowScriptBinarySectionHeader.SIZE + (mStringSection.Count * sizeof(byte)));

            return size;
        }

        private int CalculateSectionCount()
        {
            int sectionCount = 0;
            if (mProcedureLabelSection != null)
                sectionCount++;

            if (mJumpLabelSection != null)
                sectionCount++;

            if (mTextSection != null)
                sectionCount++;

            if (mMessageScriptSection != null)
                sectionCount++;

            if (mStringSection != null)
                sectionCount++;

            return sectionCount;
        }

        private short CalculateLocalIntVariableCount()
        {
            int highestIndex = -1;
            for (int i = 0; i < mTextSection.Count; i++)
            {
                var instruction = mTextSection[i];

                if (instruction.Opcode == FlowScriptOpcode.POPLIX || instruction.Opcode == FlowScriptOpcode.PUSHLIX)
                {
                    // check if it's a false positive
                    if (i - 1 != -1 && (mTextSection[i - 1].Opcode == FlowScriptOpcode.PUSHI || mTextSection[i - 1].Opcode == FlowScriptOpcode.PUSHF))
                    {
                        continue;
                    }

                    if (instruction.OperandShort > highestIndex)
                        highestIndex = instruction.OperandShort;
                }
            }
            
            return (short)(highestIndex + 1);
        }

        private short CalculateLocalFloatVariableCount()
        {
            int highestIndex = -1;
            for (int i = 0; i < mTextSection.Count; i++)
            {
                var instruction = mTextSection[i];

                if (instruction.Opcode == FlowScriptOpcode.POPLFX || instruction.Opcode == FlowScriptOpcode.PUSHLFX)
                {
                    // check if it's a false positive
                    if (i - 1 != -1 && (mTextSection[i - 1].Opcode == FlowScriptOpcode.PUSHI || mTextSection[i - 1].Opcode == FlowScriptOpcode.PUSHF))
                    {
                        continue;
                    }

                    if (instruction.OperandShort > highestIndex)
                        highestIndex = instruction.OperandShort;
                }
            }

            return (short)(highestIndex + 1);
        }
    }
}
