using System.Collections.ObjectModel;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Collections.Generic;
using System.Text;

using AtlusScriptLib.Shared.IO;
using AtlusScriptLib.Shared.Utilities;

namespace AtlusScriptLib.FlowScript
{
    public class FlowScriptBinary
    {
        // Headers    
        private FlowScriptBinaryHeader m_Header;
        private FlowScriptBinarySectionHeader[] m_SectionHeaders;

        // Sections
        private FlowScriptBinaryLabel[] m_ProcedureLabelSectionData;
        private FlowScriptBinaryLabel[] m_JumpLabelSectionData;
        private FlowScriptBinaryInstruction[] m_TextSectionData;
        private byte[] m_MessageScriptSectionData; // TODO: use a binary message script header here?
        private Dictionary<int, string> m_StringSectionData;

        // Properties
        public FlowScriptBinaryHeader Header
        {
            get { return m_Header; }
        }

        public ReadOnlyCollection<FlowScriptBinarySectionHeader> SectionHeaders
        {
            get { return new ReadOnlyCollection<FlowScriptBinarySectionHeader>(m_SectionHeaders); }
        }

        public ReadOnlyCollection<FlowScriptBinaryLabel> ProcedureLabelSectionData
        {
            get { return new ReadOnlyCollection<FlowScriptBinaryLabel>(m_ProcedureLabelSectionData); }
        }

        public ReadOnlyCollection<FlowScriptBinaryLabel> JumpLabelSectionData
        {
            get { return new ReadOnlyCollection<FlowScriptBinaryLabel>(m_JumpLabelSectionData); }
        }

        public ReadOnlyCollection<FlowScriptBinaryInstruction> TextSectionData
        {
            get { return new ReadOnlyCollection<FlowScriptBinaryInstruction>(m_TextSectionData); }
        }

        public ReadOnlyCollection<byte> MessageScriptSectionData
        {
            get { return new ReadOnlyCollection<byte>(m_MessageScriptSectionData); }
        }

        public ReadOnlyDictionary<int, string> StringSectionData
        {
            get { return new ReadOnlyDictionary<int, string>(m_StringSectionData); }
        }

        public FlowScriptBinaryVersion Version
        {
            get;
            private set;
        }

        private FlowScriptBinary()
        {
        }

        // Static methods
        public static FlowScriptBinaryLoadResult LoadFromFile(string path, FlowScriptBinaryVersion version, out FlowScriptBinary script)
        {
            using (var fileStream = File.OpenRead(path))
            {
                return LoadFromStream(fileStream, version, out script);
            }
        }

        public static FlowScriptBinaryLoadResult LoadFromFile(string path, out FlowScriptBinary script)
        {
            return LoadFromFile(path, FlowScriptBinaryVersion.Unknown, out script);
        }

        public static FlowScriptBinaryLoadResult LoadFromStream(Stream stream, FlowScriptBinaryVersion version, out FlowScriptBinary script)
        {
            script = new FlowScriptBinary();

            using (EndianBinaryReader reader = new EndianBinaryReader(stream, version.HasFlag(FlowScriptBinaryVersion.BE) ? Endianness.BigEndian : Endianness.LittleEndian))
            {
                script.Version = version;

                // Check if the stream isn't too small to be a proper file
                if (stream.Length < FlowScriptBinaryHeader.SIZE)
                {
                    Trace.TraceError("Stream is too small to be a proper script file.");
                    script = null;
                    return FlowScriptBinaryLoadResult.InvalidFormat;
                }
                else
                {
                    script.m_Header = reader.ReadStruct<FlowScriptBinaryHeader>();
                    if (!script.m_Header.Magic.SequenceEqual(FlowScriptBinaryHeader.MAGIC))
                    {
                        Trace.TraceError("Magic signature value does not match");
                        script = null;
                        return FlowScriptBinaryLoadResult.InvalidFormat;
                    }
                }

                // Swap endianness if high bits of section count are used
                if ((script.m_Header.SectionCount & 0xFF000000) != 0)
                { 
                    script.m_Header = EndiannessHelper.SwapEndianness(script.m_Header);

                    if (reader.Endianness == Endianness.LittleEndian)
                    {
                        reader.Endianness = Endianness.BigEndian;
                        script.Version |= FlowScriptBinaryVersion.BE;
                    }
                    else
                    {
                        reader.Endianness = Endianness.LittleEndian;
                        script.Version ^= FlowScriptBinaryVersion.BE;
                    }
                }

                // Read section headers
                script.m_SectionHeaders = new FlowScriptBinarySectionHeader[script.m_Header.SectionCount];
                for (int i = 0; i < script.m_SectionHeaders.Length; i++)
                {
                    script.m_SectionHeaders[i] = reader.ReadStruct<FlowScriptBinarySectionHeader>();
                }

                // Parse sections using the section headers
                foreach (var sectionHeader in script.m_SectionHeaders)
                {
                    if (!(sectionHeader.StartOffset + (sectionHeader.UnitSize * sectionHeader.UnitCount) <= stream.Length))
                    {
                        DebugUtils.TraceError("Stream is too small for the amount of data described. File is likely truncated");
                        script = null;
                        return FlowScriptBinaryLoadResult.InvalidFormat;
                    }

                    reader.SeekBegin(sectionHeader.StartOffset);

                    FlowScriptBinaryLoadResult result;

                    switch (sectionHeader.sectionType)
                    {
                        case FlowScriptBinarySectionType.ProcedureLabelSection:
                            result = ReadLabelSectionData(reader, script, sectionHeader, out script.m_ProcedureLabelSectionData);
                            break;

                        case FlowScriptBinarySectionType.JumpLabelSection:
                            result = ReadLabelSectionData(reader, script, sectionHeader, out script.m_JumpLabelSectionData);
                            break;

                        case FlowScriptBinarySectionType.TextSection:
                            result = ReadTextSectionData(reader, script, sectionHeader);
                            break;

                        case FlowScriptBinarySectionType.MessageScriptSection:
                            result = ReadMessageScriptSectionData(reader, script, sectionHeader);
                            break;

                        case FlowScriptBinarySectionType.StringSection:
                            result = ReadStringSectionData(reader, script, sectionHeader);
                            break;

                        default:
                            DebugUtils.TraceError($"BinaryFlowScript::LoadFromStream: unknown section id {sectionHeader.sectionType}");
                            return FlowScriptBinaryLoadResult.InvalidFormat;
                    }

                    if (result != FlowScriptBinaryLoadResult.OK)
                        return result;
                }
            }

            return FlowScriptBinaryLoadResult.OK;
        }

        public static FlowScriptBinaryLoadResult LoadFromStream(Stream stream, out FlowScriptBinary script)
        {
            return LoadFromStream(stream, FlowScriptBinaryVersion.Unknown, out script);
        }

        private static FlowScriptBinaryLoadResult ReadLabelSectionData(EndianBinaryReader reader, FlowScriptBinary script, FlowScriptBinarySectionHeader sectionHeader, out FlowScriptBinaryLabel[] labels)
        {
            if (sectionHeader.UnitSize != FlowScriptBinaryLabel.SIZE_V1 &&
                sectionHeader.UnitSize != FlowScriptBinaryLabel.SIZE_V2 &&
                sectionHeader.UnitSize != FlowScriptBinaryLabel.SIZE_V3)
            {
                DebugUtils.TraceError("Unknown unit size for label");

                labels = null;
                return FlowScriptBinaryLoadResult.InvalidFormat;
            }

            if (sectionHeader.UnitSize == FlowScriptBinaryLabel.SIZE_V1 && !script.Version.HasFlag(FlowScriptBinaryVersion.V1))
            {
                script.Version = FlowScriptBinaryVersion.V1;
                if (reader.Endianness == Endianness.BigEndian)
                    script.Version |= FlowScriptBinaryVersion.BE;
            }
            else if (sectionHeader.UnitSize == FlowScriptBinaryLabel.SIZE_V2 && !script.Version.HasFlag(FlowScriptBinaryVersion.V2))
            {
                script.Version = FlowScriptBinaryVersion.V2;
                if (reader.Endianness == Endianness.BigEndian)
                    script.Version |= FlowScriptBinaryVersion.BE;
            }
            else if (sectionHeader.UnitSize == FlowScriptBinaryLabel.SIZE_V3 && !script.Version.HasFlag(FlowScriptBinaryVersion.V3))
            {
                script.Version = FlowScriptBinaryVersion.V3;
                if (reader.Endianness == Endianness.BigEndian)
                    script.Version |= FlowScriptBinaryVersion.BE;
            }

            labels = new FlowScriptBinaryLabel[sectionHeader.UnitCount];
            for (int i = 0; i < labels.Length; i++)
            {
                var label = new FlowScriptBinaryLabel()
                {
                    Name = reader.ReadCString(sectionHeader.UnitSize - sizeof(int) * 2),
                    Offset = reader.ReadInt32(),
                    Reserved = reader.ReadInt32()
                };

                // Would indicate a possible endianness issue
                Trace.Assert(label.Offset < int.MaxValue, "Invalid label offset");

                // Should be zero
                Trace.Assert(label.Reserved == 0, "Label reserved field isn't 0");

                labels[i] = label;
            }

            return FlowScriptBinaryLoadResult.OK;
        }

        private static FlowScriptBinaryLoadResult ReadTextSectionData(EndianBinaryReader reader, FlowScriptBinary script, FlowScriptBinarySectionHeader sectionHeader)
        {
            if (!(sectionHeader.UnitSize == FlowScriptBinaryInstructionInternal.SIZE))
            {
                DebugUtils.TraceError($"{FlowScriptBinarySectionType.TextSection} unit size must be 1");
                return FlowScriptBinaryLoadResult.InvalidFormat;
            }

            // HACK: the instructions are stored in an union consisting of 2 shorts, an int and a float
            // due to endianness swapping, this union isn't portable in the sense that it retains the field order as the 2 shorts would be swapped around
            // so we read instructions in system native endianness, and fix them up later

            Endianness sourceEndianness = reader.Endianness;
            bool needsSwap = reader.EndiannessNeedsSwapping;

            if (needsSwap)
                reader.Endianness = EndiannessHelper.SystemEndianness;

            script.m_TextSectionData = new FlowScriptBinaryInstruction[sectionHeader.UnitCount];
            for (int i = 0; i < script.m_TextSectionData.Length; i++)
            {
                var instruction = reader.ReadStruct<FlowScriptBinaryInstructionInternal>();

                var instructionAux = new FlowScriptBinaryInstruction()
                {
                    Opcode = instruction.Opcode,
                    OperandShort = instruction.OperandShort,
                    OperandInt = instruction.OperandInt,
                    OperandFloat = instruction.OperandFloat,
                };

                if (needsSwap)
                {
                    instructionAux = EndiannessHelper.SwapEndianness(instructionAux);
                }

                script.m_TextSectionData[i] = instructionAux;
            }

            // HACK: set endianness back to what it was before we swapped it to fix the issue mentioning above
            if (needsSwap)
                reader.Endianness = sourceEndianness;

            return FlowScriptBinaryLoadResult.OK;
        }

        private static FlowScriptBinaryLoadResult ReadMessageScriptSectionData(EndianBinaryReader reader, FlowScriptBinary script, FlowScriptBinarySectionHeader sectionHeader)
        {
            if (!(sectionHeader.UnitSize == sizeof(byte)))
            {
                DebugUtils.TraceError($"{FlowScriptBinarySectionType.MessageScriptSection} unit size must be 1");
                return FlowScriptBinaryLoadResult.InvalidFormat;
            }

            script.m_MessageScriptSectionData = reader.ReadBytes((int)sectionHeader.UnitCount);

            return FlowScriptBinaryLoadResult.OK;
        }

        private static FlowScriptBinaryLoadResult ReadStringSectionData(EndianBinaryReader reader, FlowScriptBinary script, FlowScriptBinarySectionHeader sectionHeader)
        {
            if (!(sectionHeader.UnitSize == sizeof(byte)))
            {
                DebugUtils.TraceError($"{FlowScriptBinarySectionType.StringSection} unit size must be 1");
                return FlowScriptBinaryLoadResult.InvalidFormat;
            }

            script.m_StringSectionData = new Dictionary<int, string>();

            int startIndex = 0;
            int index = 0;
            StringBuilder builder = new StringBuilder();

            while (index < sectionHeader.UnitCount)
            {
                index++;

                byte b = reader.ReadByte();
                if (b != 0)
                {
                    builder.Append((char)b);
                }
                else if (builder.Length != 0)
                {
                    script.m_StringSectionData[startIndex] = builder.ToString();
                    builder.Clear();

                    startIndex = index;
                }           
            }

            return FlowScriptBinaryLoadResult.OK;
        }
    }
}
