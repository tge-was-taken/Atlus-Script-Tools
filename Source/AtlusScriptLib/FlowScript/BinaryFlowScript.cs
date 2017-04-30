using System.Collections.ObjectModel;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Collections.Generic;
using System.Text;

using AtlusScriptLib.IO;
using AtlusScriptLib.Utilities;

namespace AtlusScriptLib.FlowScript
{
    public class BinaryFlowScript
    {
        // Headers    
        private BinaryFlowScriptHeader m_Header;
        private BinaryFlowScriptSectionHeader[] m_SectionHeaders;

        // Sections
        private BinaryFlowScriptLabel[] m_ProcedureLabelSectionData;
        private BinaryFlowScriptLabel[] m_JumpLabelSectionData;
        private BinaryFlowScriptInstruction[] m_TextSectionData;
        private byte[] m_MessageScriptSectionData; // todo: use a binary message script header here?
        private Dictionary<int, string> m_StringSectionData;

        private BinaryFlowScript()
        {
        }

        // Properties
        public BinaryFlowScriptHeader Header
        {
            get { return m_Header; }
        }

        public ReadOnlyCollection<BinaryFlowScriptSectionHeader> SectionHeaders
        {
            get { return new ReadOnlyCollection<BinaryFlowScriptSectionHeader>(m_SectionHeaders); }
        }

        public ReadOnlyCollection<BinaryFlowScriptLabel> ProcedureLabelSectionData
        {
            get { return new ReadOnlyCollection<BinaryFlowScriptLabel>(m_ProcedureLabelSectionData); }
        }

        public ReadOnlyCollection<BinaryFlowScriptLabel> JumpLabelSectionData
        {
            get { return new ReadOnlyCollection<BinaryFlowScriptLabel>(m_JumpLabelSectionData); }
        }

        public ReadOnlyCollection<BinaryFlowScriptInstruction> TextSectionData
        {
            get { return new ReadOnlyCollection<BinaryFlowScriptInstruction>(m_TextSectionData); }
        }

        public ReadOnlyCollection<byte> MessageScriptSectionData
        {
            get { return new ReadOnlyCollection<byte>(m_MessageScriptSectionData); }
        }

        public ReadOnlyDictionary<int, string> StringSectionData
        {
            get { return new ReadOnlyDictionary<int, string>(m_StringSectionData); }
        }

        public BinaryFlowScriptVersion Version
        {
            get;
            private set;
        }

        // Static methods
        public static BinaryFlowScriptLoadResult LoadFromFile(string path, BinaryFlowScriptVersion version, out BinaryFlowScript script)
        {
            using (var fileStream = File.OpenRead(path))
            {
                return LoadFromStream(fileStream, version, out script);
            }
        }

        public static BinaryFlowScriptLoadResult LoadFromStream(Stream stream, BinaryFlowScriptVersion version, out BinaryFlowScript script)
        {
            script = new BinaryFlowScript();

            using (EndianBinaryReader reader = new EndianBinaryReader(stream, version.HasFlag(BinaryFlowScriptVersion.BE) ? Endianness.BigEndian : Endianness.LittleEndian))
            {
                script.Version = version;

                // Check if the stream isn't too small to be a proper file
                if (stream.Length < BinaryFlowScriptHeader.SIZE)
                {
                    Trace.TraceError("Stream is too small to be a proper script file.");
                    script = null;
                    return BinaryFlowScriptLoadResult.InvalidFormat;
                }
                else
                {
                    script.m_Header = reader.ReadStruct<BinaryFlowScriptHeader>();
                    if (!script.m_Header.Magic.SequenceEqual(BinaryFlowScriptHeader.MAGIC))
                    {
                        Trace.TraceError("Magic signature value does not match");
                        script = null;
                        return BinaryFlowScriptLoadResult.InvalidFormat;
                    }
                }

                // Swap endianness if high bits of section count are used
                if ((script.m_Header.SectionCount & 0xFF000000) != 0)
                { 
                    script.m_Header = EndiannessHelper.SwapEndianness(script.m_Header);

                    if (reader.Endianness == Endianness.LittleEndian)
                    {
                        reader.Endianness = Endianness.BigEndian;
                        script.Version |= BinaryFlowScriptVersion.BE;
                    }
                    else
                    {
                        reader.Endianness = Endianness.LittleEndian;
                        script.Version ^= BinaryFlowScriptVersion.BE;
                    }
                }

                // Read section headers
                script.m_SectionHeaders = new BinaryFlowScriptSectionHeader[script.m_Header.SectionCount];
                for (int i = 0; i < script.m_SectionHeaders.Length; i++)
                {
                    script.m_SectionHeaders[i] = reader.ReadStruct<BinaryFlowScriptSectionHeader>();
                }

                // Parse sections using the section headers
                foreach (var sectionHeader in script.m_SectionHeaders)
                {
                    if (!(sectionHeader.StartOffset + (sectionHeader.UnitSize * sectionHeader.UnitCount) <= stream.Length))
                    {
                        DebugUtils.TraceError("Stream is too small for the amount of data described. File is likely truncated");
                        script = null;
                        return BinaryFlowScriptLoadResult.InvalidFormat;
                    }

                    reader.SeekBegin(sectionHeader.StartOffset);

                    BinaryFlowScriptLoadResult result;

                    switch (sectionHeader.sectionType)
                    {
                        case BinaryFlowScriptSectionType.ProcedureLabelSection:
                            result = ReadLabelSectionData(reader, script, sectionHeader, out script.m_ProcedureLabelSectionData);
                            break;

                        case BinaryFlowScriptSectionType.JumpLabelSection:
                            result = ReadLabelSectionData(reader, script, sectionHeader, out script.m_JumpLabelSectionData);
                            break;

                        case BinaryFlowScriptSectionType.TextSection:
                            result = ReadTextSectionData(reader, script, sectionHeader);
                            break;

                        case BinaryFlowScriptSectionType.MessageScriptSection:
                            result = ReadMessageScriptSectionData(reader, script, sectionHeader);
                            break;

                        case BinaryFlowScriptSectionType.StringSection:
                            result = ReadStringSectionData(reader, script, sectionHeader);
                            break;

                        default:
                            DebugUtils.TraceError($"BinaryFlowScript::LoadFromStream: unknown section id {sectionHeader.sectionType}");
                            return BinaryFlowScriptLoadResult.InvalidFormat;
                    }

                    if (result != BinaryFlowScriptLoadResult.OK)
                        return result;
                }
            }

            return BinaryFlowScriptLoadResult.OK;
        }

        private static BinaryFlowScriptLoadResult ReadLabelSectionData(EndianBinaryReader reader, BinaryFlowScript script, BinaryFlowScriptSectionHeader sectionHeader, out BinaryFlowScriptLabel[] labels)
        {
            if (sectionHeader.UnitSize != BinaryFlowScriptLabel.SIZE_V1 &&
                sectionHeader.UnitSize != BinaryFlowScriptLabel.SIZE_V2 &&
                sectionHeader.UnitSize != BinaryFlowScriptLabel.SIZE_V3)
            {
                DebugUtils.TraceError("Unknown unit size for label");

                labels = null;
                return BinaryFlowScriptLoadResult.InvalidFormat;
            }

            if (sectionHeader.UnitSize == BinaryFlowScriptLabel.SIZE_V1 && !script.Version.HasFlag(BinaryFlowScriptVersion.V1))
            {
                script.Version = BinaryFlowScriptVersion.V1;
                if (reader.Endianness == Endianness.BigEndian)
                    script.Version |= BinaryFlowScriptVersion.BE;
            }
            else if (sectionHeader.UnitSize == BinaryFlowScriptLabel.SIZE_V2 && !script.Version.HasFlag(BinaryFlowScriptVersion.V2))
            {
                script.Version = BinaryFlowScriptVersion.V2;
                if (reader.Endianness == Endianness.BigEndian)
                    script.Version |= BinaryFlowScriptVersion.BE;
            }
            else if (sectionHeader.UnitSize == BinaryFlowScriptLabel.SIZE_V3 && !script.Version.HasFlag(BinaryFlowScriptVersion.V3))
            {
                script.Version = BinaryFlowScriptVersion.V3;
                if (reader.Endianness == Endianness.BigEndian)
                    script.Version |= BinaryFlowScriptVersion.BE;
            }

            labels = new BinaryFlowScriptLabel[sectionHeader.UnitCount];
            for (int i = 0; i < labels.Length; i++)
            {
                var label = new BinaryFlowScriptLabel()
                {
                    Name = reader.ReadCString((int)sectionHeader.UnitSize - sizeof(uint) * 2),
                    Offset = reader.ReadUInt32(),
                    Reserved = reader.ReadUInt32()
                };

                // Would indicate a possible endianness issue
                Trace.Assert(label.Offset < int.MaxValue, "Invalid label offset");

                // Should be zero
                Trace.Assert(label.Reserved == 0, "Label reserved field isn't 0");

                labels[i] = label;
            }

            return BinaryFlowScriptLoadResult.OK;
        }

        private static BinaryFlowScriptLoadResult ReadTextSectionData(EndianBinaryReader reader, BinaryFlowScript script, BinaryFlowScriptSectionHeader sectionHeader)
        {
            if (!(sectionHeader.UnitSize == BinaryFlowScriptInstructionInternal.SIZE))
            {
                DebugUtils.TraceError($"{BinaryFlowScriptSectionType.TextSection} unit size must be 1");
                return BinaryFlowScriptLoadResult.InvalidFormat;
            }

            // HACK: the instructions are stored in a tuple consisting of 2 shorts, an int and a float
            // due to endianness swapping, this tuple isn't portable in the sense that it retains the field order as the 2 shorts would be swapped around
            // so we read instructions in system native endianness, and fix them up later

            Endianness sourceEndianness = reader.Endianness;
            bool needsSwap = reader.EndiannessNeedsSwapping;

            if (needsSwap)
                reader.Endianness = EndiannessHelper.SystemEndianness;

            script.m_TextSectionData = new BinaryFlowScriptInstruction[sectionHeader.UnitCount];
            for (int i = 0; i < script.m_TextSectionData.Length; i++)
            {
                var instruction = reader.ReadStruct<BinaryFlowScriptInstructionInternal>();

                var instructionAux = new BinaryFlowScriptInstruction()
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

                //if (script.m_TextSectionData[i].Opcode == BinaryFlowScriptOpcode.PUSHF)
                    //DebugUtils.DebugBreak();
            }

            // HACK: set endianness back to what it was before we swapped it to fix the issue mentioning above
            if (needsSwap)
                reader.Endianness = sourceEndianness;

            return BinaryFlowScriptLoadResult.OK;
        }

        private static BinaryFlowScriptLoadResult ReadMessageScriptSectionData(EndianBinaryReader reader, BinaryFlowScript script, BinaryFlowScriptSectionHeader sectionHeader)
        {
            if (!(sectionHeader.UnitSize == sizeof(byte)))
            {
                DebugUtils.TraceError($"{BinaryFlowScriptSectionType.MessageScriptSection} unit size must be 1");
                return BinaryFlowScriptLoadResult.InvalidFormat;
            }

            script.m_MessageScriptSectionData = reader.ReadBytes((int)sectionHeader.UnitCount);

            return BinaryFlowScriptLoadResult.OK;
        }

        private static BinaryFlowScriptLoadResult ReadStringSectionData(EndianBinaryReader reader, BinaryFlowScript script, BinaryFlowScriptSectionHeader sectionHeader)
        {
            if (!(sectionHeader.UnitSize == sizeof(byte)))
            {
                DebugUtils.TraceError($"{BinaryFlowScriptSectionType.StringSection} unit size must be 1");
                return BinaryFlowScriptLoadResult.InvalidFormat;
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

            return BinaryFlowScriptLoadResult.OK;
        }
    }
}
