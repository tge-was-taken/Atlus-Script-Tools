using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AtlusScriptLib
{
    public sealed class FlowScript
    {
        private short mUserId, mLocalIntVariableCount, mLocalFloatVariableCount;
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

        public short LocalIntVariableCount
        {
            get { return mLocalIntVariableCount; }
        }

        public short LocalFloatVariableCount
        {
            get { return mLocalFloatVariableCount; }
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
            mLocalIntVariableCount = 0;
            mLocalFloatVariableCount = 0;
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
            instance.mUserId                  = binary.Header.UserId;
            instance.mLocalIntVariableCount   = binary.Header.LocalIntVariableCount;
            instance.mLocalFloatVariableCount = binary.Header.LocalFloatVariableCount;

            // assign labels later as we convert the instructions because we need to update the instruction indices
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

            // assign instructions
            if (binary.TextSection != null)
            {
                int instructionIndex = 0;
                int instructionBinaryIndex = 0;

                while( instructionBinaryIndex < binary.TextSection.Count )
                {
                    // Check if there are any procedure labels that map to the current binary index, and reassign its instruction index
                    // With the value of the current instruction index into the list we're creating
                    foreach (var label in binary.ProcedureLabelSection.Where(x => x.InstructionIndex == instructionBinaryIndex))
                    {
                        instance.mProcedureLabels.Add(new FlowScriptLabel(label.Name, instructionIndex));
                    }

                    // Same goes for the jump labels
                    foreach (var label in binary.JumpLabelSection.Where(x => x.InstructionIndex == instructionBinaryIndex))
                    {
                        instance.mJumpLabels.Add(new FlowScriptLabel(label.Name, instructionIndex));
                    }

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
    }
}
