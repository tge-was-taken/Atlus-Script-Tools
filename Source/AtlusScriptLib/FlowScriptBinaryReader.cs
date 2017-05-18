using System;
using System.IO;
using System.Linq;
using AtlusScriptLib.Common.IO;

namespace AtlusScriptLib
{
    public class FlowScriptBinaryReader : IDisposable
    {
        private long mPositionBase;
        private EndianBinaryReader mReader;     
        private FlowScriptBinaryFormatVersion mVersion;

        public FlowScriptBinaryReader(Stream stream, FlowScriptBinaryFormatVersion version)
        {
            mPositionBase = stream.Position;
            mReader = new EndianBinaryReader(stream, version.HasFlag(FlowScriptBinaryFormatVersion.BE) ? Endianness.BigEndian : Endianness.LittleEndian);
            mVersion = version;
        }

        public FlowScriptBinaryHeader ReadHeader()
        {
            FlowScriptBinaryHeader header;

            // Check if the stream isn't too small to be a proper file
            if (mReader.BaseStreamLength < FlowScriptBinaryHeader.SIZE)
            {
                throw new InvalidDataException("Stream is too small to be valid");
            }
            else
            {
                header = mReader.ReadStruct<FlowScriptBinaryHeader>();
                if (!header.Magic.SequenceEqual(FlowScriptBinaryHeader.MAGIC))
                {
                    throw new InvalidDataException("Header magic value does not match");
                }
            }

            // Swap endianness if high bits of section count are used
            if ((header.SectionCount & 0xFF000000) != 0)
            {
                header = EndiannessHelper.SwapEndianness(header);

                if (mReader.Endianness == Endianness.LittleEndian)
                {
                    mReader.Endianness = Endianness.BigEndian;
                    mVersion |= FlowScriptBinaryFormatVersion.BE;
                }
                else
                {
                    mReader.Endianness = Endianness.LittleEndian;
                    mVersion ^= FlowScriptBinaryFormatVersion.BE;
                }
            }

            return header;
        }

        public FlowScriptBinarySectionHeader[] ReadSectionHeaders(ref FlowScriptBinaryHeader header)
        {
            return mReader.ReadStruct<FlowScriptBinarySectionHeader>(header.SectionCount);
        }

        public FlowScriptBinaryLabel[] ReadLabelSection(ref FlowScriptBinarySectionHeader sectionHeader)
        {
            PerformBeforeSectionReadActions(ref sectionHeader);

            if (sectionHeader.ElementSize != FlowScriptBinaryLabel.SIZE_V1 &&
                sectionHeader.ElementSize != FlowScriptBinaryLabel.SIZE_V2 &&
                sectionHeader.ElementSize != FlowScriptBinaryLabel.SIZE_V3)
            {
                throw new InvalidDataException("Unknown size for label");
            }

            if (sectionHeader.ElementSize == FlowScriptBinaryLabel.SIZE_V1 && !mVersion.HasFlag(FlowScriptBinaryFormatVersion.V1))
            {
                mVersion = FlowScriptBinaryFormatVersion.V1;
                if (mReader.Endianness == Endianness.BigEndian)
                    mVersion |= FlowScriptBinaryFormatVersion.BE;
            }
            else if (sectionHeader.ElementSize == FlowScriptBinaryLabel.SIZE_V2 && !mVersion.HasFlag(FlowScriptBinaryFormatVersion.V2))
            {
                mVersion = FlowScriptBinaryFormatVersion.V2;
                if (mReader.Endianness == Endianness.BigEndian)
                    mVersion |= FlowScriptBinaryFormatVersion.BE;
            }
            else if (sectionHeader.ElementSize == FlowScriptBinaryLabel.SIZE_V3 && !mVersion.HasFlag(FlowScriptBinaryFormatVersion.V3))
            {
                mVersion = FlowScriptBinaryFormatVersion.V3;
                if (mReader.Endianness == Endianness.BigEndian)
                    mVersion |= FlowScriptBinaryFormatVersion.BE;
            }

            var labels = new FlowScriptBinaryLabel[sectionHeader.ElementCount];

            for (int i = 0; i < labels.Length; i++)
            {
                var label = new FlowScriptBinaryLabel()
                {
                    Name = mReader.ReadString(StringBinaryFormat.FixedLength, sectionHeader.ElementSize - (sizeof(int) * 2)),
                    InstructionIndex = mReader.ReadInt32(),
                    Reserved = mReader.ReadInt32()
                };

                // Would indicate a possible endianness issue
                if (label.InstructionIndex >= int.MaxValue)
                {
                    throw new InvalidDataException("Invalid label offset");
                }

                // Should be zero
                if (label.Reserved != 0)
                {
                    throw new InvalidDataException("Label reserved field isn't 0");
                }

                labels[i] = label;
            }

            return labels;
        }

        public FlowScriptBinaryInstruction[] ReadTextSection(ref FlowScriptBinarySectionHeader sectionHeader)
        {
            PerformBeforeSectionReadActions(ref sectionHeader);

            if (sectionHeader.ElementSize != FlowScriptBinaryInstruction.SIZE)
            {
                throw new InvalidDataException($"{FlowScriptBinarySectionType.TextSection} unit size must be 4");
            }

            // HACK: the instructions are stored in an union consisting of 2 shorts, an int and a float
            // due to endianness swapping, this union isn't portable in the sense that it retains the field order as the 2 shorts would be swapped around
            // so we read instructions in system native endianness, and fix them up later

            Endianness sourceEndianness = mReader.Endianness;
            bool needsSwap = mReader.EndiannessNeedsSwapping;

            if (needsSwap)
                mReader.Endianness = EndiannessHelper.SystemEndianness;

            var instructions = new FlowScriptBinaryInstruction[sectionHeader.ElementCount];
            for (int i = 0; i < instructions.Length; i++)
            {
                uint instructionValue = mReader.ReadUInt32();

                // Opcode
                short opcode = (short)Bitwise.Extract(instructionValue, 0, 15);

                // Short operand
                short operandShort = (short)Bitwise.Extract(instructionValue, 16, 31);

                // Int operand
                int operandInt = (int)instructionValue;

                // Float operand
                float operandFloat = Unsafe.ReinterpretCast<uint, float>(instructionValue);

                if (needsSwap)
                {
                    opcode = EndiannessHelper.SwapEndianness(opcode); 
                    operandShort = EndiannessHelper.SwapEndianness(operandShort);
                    operandInt = EndiannessHelper.SwapEndianness(operandInt);
                    operandFloat = EndiannessHelper.SwapEndianness(operandFloat);
                }

                // Fill in struct
                FlowScriptBinaryInstruction instruction = new FlowScriptBinaryInstruction();
                instruction.Opcode = (FlowScriptOpcode)opcode;
                instruction.OperandShort = operandShort;
                //instruction.OperandInt = operandInt;
                //instruction.OperandFloat = operandFloat;

                instructions[i] = instruction;
            }

            // HACK: set endianness back to what it was before we swapped it to fix the issue mentioning above
            if (needsSwap)
                mReader.Endianness = sourceEndianness;

            return instructions;
        }

        public byte[] ReadMessageScriptSection(ref FlowScriptBinarySectionHeader sectionHeader)
        {
            PerformBeforeSectionReadActions(ref sectionHeader);

            if (sectionHeader.ElementSize != sizeof(byte))
            {
                throw new InvalidDataException($"{FlowScriptBinarySectionType.MessageScriptSection} unit size must be 1");
            }

            return mReader.ReadBytes(sectionHeader.ElementCount);
        }

        public byte[] ReadStringSection(ref FlowScriptBinarySectionHeader sectionHeader)
        {
            PerformBeforeSectionReadActions(ref sectionHeader);

            if (sectionHeader.ElementSize != sizeof(byte))
            {
                throw new InvalidDataException($"{FlowScriptBinarySectionType.StringSection} unit size must be 1");
            }

            return mReader.ReadBytes(sectionHeader.ElementCount);
        }

        public FlowScriptBinaryFormatVersion GetDetectedFormatVersion()
        {
            return mVersion;
        }

        public void Dispose()
        {
            ((IDisposable)mReader).Dispose();
        }

        private void PerformBeforeSectionReadActions(ref FlowScriptBinarySectionHeader sectionHeader)
        {
            if (sectionHeader.FirstElementAddress == IOConstants.NullPointer)
            {
                throw new InvalidOperationException("Section start offset is a null pointer");
            }

            long absoluteAddress = mPositionBase + sectionHeader.FirstElementAddress;

            if (!(absoluteAddress + (sectionHeader.ElementSize * sectionHeader.ElementCount) <= mReader.BaseStreamLength))
            {
                throw new InvalidDataException("Stream is too small for the amount of data described. File is likely truncated");
            }

            mReader.SeekBegin(absoluteAddress);
        }
    }
}
