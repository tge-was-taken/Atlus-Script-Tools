using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AtlusScriptLib
{
    public sealed class FlowScript
    {
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
            FlowScript instance = new FlowScript()
            {
                mUserId = binary.Header.UserId
            };

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
                    // check for string terminator or end of string section
                    if (binary.StringSection[i] == 0 || i + 1 == binary.StringSection.Count)
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

                while (instructionBinaryIndex < binary.TextSection.Count)
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

        // Instance fields
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

        public FlowScriptBinary ToBinary()
        {
            var builder = new FlowScriptBinaryBuilder(mFormatVersion);
            builder.SetUserId(mUserId);

            // Skip the labels until after the instructions have been converted, as we need to fix up
            // the instruction indices

            // Convert string table before the instructions so we can fix up string instructions later
            // by building an index remap table
            var stringIndexToBinaryStringIndexMap = new Dictionary<short, short>();

            if (mStrings.Count > 0)
            {
                for (short stringIndex = 0; stringIndex < mStrings.Count; stringIndex++)
                {
                    builder.AddString(mStrings[stringIndex], out int binaryIndex);
                    stringIndexToBinaryStringIndexMap[stringIndex] = (short)binaryIndex;
                }                
            }

            // Convert instructions, build an instruction index remap table & remap string indices where necessary
            int instructionListIndex = 0;
            int instructionBinaryIndex = 0;
            var instructionListIndexToBinaryIndexMap = new Dictionary<int, int>();

            for (; instructionListIndex < mInstructions.Count; instructionListIndex++)
            {
                instructionListIndexToBinaryIndexMap[instructionListIndex] = instructionBinaryIndex;

                var instruction = mInstructions[instructionListIndex];

                if (!instruction.UsesTwoBinaryInstructions)
                {
                    var binaryInstruction = new FlowScriptBinaryInstruction()
                    {
                        Opcode = instruction.Opcode
                    };

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
            foreach (var label in mProcedureLabels)
            {
                builder.AddProcedureLabel(new FlowScriptBinaryLabel() { InstructionIndex = instructionListIndexToBinaryIndexMap[label.InstructionIndex], Name = label.Name, Reserved = 0 });
            }

            foreach (var label in mJumpLabels)
            {
                builder.AddJumpLabel(new FlowScriptBinaryLabel() { InstructionIndex = instructionListIndexToBinaryIndexMap[label.InstructionIndex], Name = label.Name, Reserved = 0 });
            }

            // Convert message script
            if (mMessageScript != null)
                builder.SetMessageScriptSection(mMessageScript);

            return builder.Build();
        }
    }
}
