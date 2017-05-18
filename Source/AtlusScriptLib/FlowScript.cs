using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace AtlusScriptLib
{
    public sealed class FlowScript
    {
        private short mUserId;
        private List<FlowScriptLabel> mProcedureLabels, mJumpLabels;
        private List<FlowScriptInstruction> mInstructions;
        private byte[] mMessageScript;
        private List<string> mStrings;
        private FlowScriptBinaryFormatVersion mFormatVersion;

        public short UserId
        {
            get { return mUserId; }
            set { mUserId = value; }
        }

        public List<FlowScriptLabel> ProcedureLabels
        {
            get { return mProcedureLabels; }
        }

        public List<FlowScriptLabel> JumpLabels
        {
            get { return mJumpLabels; }
        }

        public List<FlowScriptInstruction> Instructions
        {
            get { return mInstructions; }
        }

        public byte[] MessageScript
        {
            get { return mMessageScript; }
            set { mMessageScript = value; }
        }

        public List<string> Strings
        {
            get { return mStrings; }
        }

        public FlowScriptBinaryFormatVersion FormatVersion
        {
            get { return mFormatVersion; }
        }

        private FlowScript()
        {
            mUserId = 0;
            mProcedureLabels = new List<FlowScriptLabel>();
            mJumpLabels = new List<FlowScriptLabel>();
            mInstructions = new List<FlowScriptInstruction>();
            mMessageScript = null;
            mStrings = new List<string>();
            mFormatVersion = FlowScriptBinaryFormatVersion.Unknown;
        }

        // Static methods
        public static FlowScript FromFile(string path)
        {
            return FromFile(path, FlowScriptBinaryFormatVersion.Unknown);
        }

        public static FlowScript FromFile(string path, FlowScriptBinaryFormatVersion version)
        {
            using (var stream = File.OpenRead(path))
                return FromStream(stream, version);
        }

        public static FlowScript FromStream(Stream stream)
        {
            return FromStream(stream, FlowScriptBinaryFormatVersion.Unknown);
        }

        public static FlowScript FromStream(Stream stream, FlowScriptBinaryFormatVersion version)
        {
            FlowScriptBinary binary = FlowScriptBinary.FromStream(stream, version);

            return FromBinary(binary);
        }

        public static FlowScript FromBinary(FlowScriptBinary binary)
        {
            FlowScript instance = new FlowScript();

            // assign header values
            instance.mUserId = binary.Header.UserId;

            // assign labels later after convert the instructions because we need to update the instruction indices
            // to reference the instructions in the list, and not the instructions in the array of instructions in the binary

            // assign strings before instructions so we can assign proper string indices as we convert the instructions
            Dictionary<short, short> stringBinaryIndexToListIndexMap = new Dictionary<short, short>();

            if (binary.StringSection != null)
            {
                short curStringBinaryIndex = 0;
                string curString = string.Empty;

                for (short i = 0; i < binary.StringSection.Count; i++)
                {
                    // check for string terminator
                    if (binary.StringSection[i] == 0)
                    {
                        instance.mStrings.Add(curString);
                        stringBinaryIndexToListIndexMap[curStringBinaryIndex] = (short)(instance.mStrings.Count - 1);

                        // next string will start at the next byte if there are any left
                        curStringBinaryIndex = (short)(i + 1);
                        curString = string.Empty;
                    }
                    else
                    {
                        curString += (char)binary.StringSection[i];
                    }
                }
            }

            var instructionBinaryIndexToListIndexMap = new Dictionary<int, int>();

            // assign instructions
            if (binary.TextSection != null)
            {
                int instructionIndex = 0;
                int instructionBinaryIndex = 0;

                while( instructionBinaryIndex < binary.TextSection.Count )
                {
                    instructionBinaryIndexToListIndexMap[instructionBinaryIndex] = instructionIndex;

                    // Convert each instruction
                    var binaryInstruction = binary.TextSection[instructionBinaryIndex];

                    FlowScriptInstruction instruction;

                    // Handle instructions we need to alter seperately
                    if (binaryInstruction.Opcode == FlowScriptOpcode.PUSHSTR)
                    {
                        // Update the string offset to reference the strings inside of the string list
                        instruction = FlowScriptInstruction.PUSHSTR(stringBinaryIndexToListIndexMap[binaryInstruction.OperandShort]);
                    }
                    else
                    {
                        instruction = FlowScriptInstruction.FromBinaryInstruction(binaryInstruction);
                    }

                    // Add to list
                    instance.mInstructions.Add(instruction);
                    instructionIndex++;

                    // Increment the instruction binary index by 2 if the current instruction takes up 2 instructions
                    if (instruction.UsesTwoBinaryInstructions)
                        instructionBinaryIndex += 2;
                    else
                        instructionBinaryIndex += 1;
                }
            }

            // assign labels as the instruction index remap table has been built
            foreach (var label in binary.ProcedureLabelSection)
            {
                instance.mProcedureLabels.Add(new FlowScriptLabel(label.Name, instructionBinaryIndexToListIndexMap[label.InstructionIndex]));
            }

            foreach (var label in binary.JumpLabelSection)
            {
                instance.mJumpLabels.Add(new FlowScriptLabel(label.Name, instructionBinaryIndexToListIndexMap[label.InstructionIndex]));
            }

            // assign message script
            if (binary.MessageScriptSection != null)
            {
                instance.mMessageScript = binary.MessageScriptSection.ToArray();
            }

            // strings have already been assigned previously, 
            // so last up is the version
            instance.mFormatVersion = binary.FormatVersion;

            // everything is assigned, return the constructed instance
            return instance;
        }

        public static FlowScriptBinary ToBinary(FlowScript script)
        {
            var builder = new FlowScriptBinaryBuilder(script.mFormatVersion);
            builder.SetUserId(script.mUserId);

            // Skip the labels until after the instructions have been converted, as we need to fix up
            // the instruction indices

            // Convert string table before the instructions so we can fix up string instructions later
            // by building an index remap table
            var stringIndexToBinaryStringIndexMap = new Dictionary<short, short>();

            if (script.mStrings.Count > 0)
            {
                var binaryStrings = new List<byte>();

                for (short stringIndex = 0; stringIndex < script.mStrings.Count; stringIndex++)
                {
                    stringIndexToBinaryStringIndexMap[stringIndex] = (short)binaryStrings.Count;
                    binaryStrings.AddRange(Encoding.GetEncoding(932).GetBytes(script.mStrings[stringIndex]));
                    binaryStrings.Add(0);
                }

                builder.SetStringSection(binaryStrings);
            }

            // Convert instructions, build an instruction index remap table & remap string indices where necessary
            int instructionListIndex = 0;
            int instructionBinaryIndex = 0;
            var instructionListIndexToBinaryIndexMap = new Dictionary<int, int>();

            for (; instructionListIndex < script.mInstructions.Count; instructionListIndex++)
            {
                instructionListIndexToBinaryIndexMap[instructionListIndex] = instructionBinaryIndex;

                var instruction = script.mInstructions[instructionListIndex];

                if (!instruction.UsesTwoBinaryInstructions)
                {
                    var binaryInstruction = new FlowScriptBinaryInstruction();
                    binaryInstruction.Opcode = instruction.Opcode;

                    // Handle PUSHSTR seperately due to difference in string index usage
                    if (instruction.Opcode == FlowScriptOpcode.PUSHSTR)
                    {
                        binaryInstruction.OperandShort = stringIndexToBinaryStringIndexMap[instruction.Operand.GetInt16Value()];
                    }
                    else
                    {
                        // Handle regular instruction
                        if (instruction.Operand != null)
                            binaryInstruction.OperandShort = instruction.Operand.GetInt16Value();
                    }

                    builder.AddInstruction(binaryInstruction);
                    instructionBinaryIndex += 1;
                }
                else
                {
                    // Handle instruction that uses the next instruction as its operand
                    var binaryInstruction = new FlowScriptBinaryInstruction() { Opcode = instruction.Opcode };
                    var binaryInstruction2 = new FlowScriptBinaryInstruction();

                    if (instruction.Operand.Type == FlowScriptInstruction.OperandValue.ValueType.Int32)
                    {
                        binaryInstruction2.OperandInt = instruction.Operand.GetInt32Value();
                    }
                    else if (instruction.Operand.Type == FlowScriptInstruction.OperandValue.ValueType.Single)
                    {
                        binaryInstruction2.OperandFloat = instruction.Operand.GetSingleValue();
                    }
                    else
                    {
                        throw new InvalidOperationException();
                    }

                    builder.AddInstruction(binaryInstruction);
                    builder.AddInstruction(binaryInstruction2);
                    instructionBinaryIndex += 2;
                }                
            }

            // Convert labels after the instructions to remap the instruction indices
            foreach (var label in script.mProcedureLabels)
            {
                builder.AddProcedureLabel(new FlowScriptBinaryLabel() { InstructionIndex = instructionListIndexToBinaryIndexMap[label.InstructionIndex], Name = label.Name, Reserved = 0 });
            }

            foreach (var label in script.mJumpLabels)
            {
                builder.AddJumpLabel(new FlowScriptBinaryLabel() { InstructionIndex = instructionListIndexToBinaryIndexMap[label.InstructionIndex], Name = label.Name, Reserved = 0 });
            }

            // Convert message script
            if (script.mMessageScript != null)
                builder.SetMessageScriptSection(script.mMessageScript);

            return builder.Build();
        }
    }
}
