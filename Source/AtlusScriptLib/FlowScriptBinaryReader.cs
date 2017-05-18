using System;
using System.IO;
using System.Linq;
using AtlusScriptLib.Common.IO;

namespace AtlusScriptLib
{
    public sealed class FlowScriptBinaryReader : IDisposable
    {
        private bool mDisposed;
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

            var instructions = new FlowScriptBinaryInstruction[sectionHeader.ElementCount];
            for (int i = 0; i < instructions.Length; i++)
            {
                FlowScriptBinaryInstruction instruction = new FlowScriptBinaryInstruction();

                if (i != 0 && instructions[i - 1].Opcode == FlowScriptOpcode.PUSHI)
                {
                    instruction.Opcode = unchecked ((FlowScriptOpcode)(-1));
                    instruction.OperandInt = mReader.ReadInt32();
                }
                else if (i != 0 && instructions[i - 1].Opcode == FlowScriptOpcode.PUSHF)
                {
                    instruction.Opcode = unchecked((FlowScriptOpcode)(-1));
                    instruction.OperandFloat = mReader.ReadSingle();
                }
                else
                {
                    instruction.Opcode = (FlowScriptOpcode)mReader.ReadInt16();
                    instruction.OperandShort = mReader.ReadInt16();
                }

                instructions[i] = instruction;
            }

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
            if (mDisposed)
                return;

            ((IDisposable)mReader).Dispose();
            mDisposed = true;
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
