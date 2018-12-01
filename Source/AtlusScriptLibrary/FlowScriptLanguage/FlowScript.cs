using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.Common.Text.Encodings;
using AtlusScriptLibrary.FlowScriptLanguage.BinaryModel;
using AtlusScriptLibrary.MessageScriptLanguage;

namespace AtlusScriptLibrary.FlowScriptLanguage
{
    /// <summary>
    /// Representation of a flow script binary optimized for use of use.
    /// </summary>
    public sealed class FlowScript
    {
        //
        // Static methods
        //

        /// <summary>
        /// Creates a <see cref="FlowScript"/> by loading it from a file.
        /// </summary>
        /// <param name="path">Path to the file to load.</param>
        /// <returns>A <see cref="FlowScript"/> instance.</returns>
        public static FlowScript FromFile( string path, Encoding encoding = null )
        {
            return FromFile( path, encoding, FormatVersion.Unknown );
        }

        /// <summary>
        /// Creates a <see cref="FlowScript"/> by loading it from a file in the specified format version.
        /// </summary>
        /// <param name="path">Path to the file to load.</param>
        /// <param name="version">Format version the loader should use.</param>
        /// <returns>A <see cref="FlowScript"/> instance.</returns>
        public static FlowScript FromFile( string path, Encoding encoding, FormatVersion version )
        {
            using ( var stream = File.OpenRead( path ) )
                return FromStream( stream, encoding, version, false );
        }

        /// <summary>
        /// Creates a <see cref="FlowScript"/> by loading it from a stream.
        /// </summary>
        /// <param name="stream">Data stream.</param>
        /// <param name="version">Format version the loader should use.</param>
        /// <returns>A <see cref="FlowScript"/> instance.</returns>
        public static FlowScript FromStream( Stream stream, Encoding encoding = null, bool leaveOpen = false )
        {
            return FromStream( stream, encoding, FormatVersion.Unknown, leaveOpen );
        }

        /// <summary>
        /// Creates a <see cref="FlowScript"/> by loading it from a stream in the specified format version.
        /// </summary>
        /// <param name="stream">Data stream.</param>
        /// <param name="version">Format version the loader should use.</param>
        /// <returns>A <see cref="FlowScript"/> instance.</returns>
        public static FlowScript FromStream( Stream stream, Encoding encoding, FormatVersion version, bool leaveOpen )
        {
            FlowScriptBinary binary = FlowScriptBinary.FromStream( stream, (BinaryFormatVersion)version, leaveOpen );

            return FromBinary( binary, encoding );
        }

        /// <summary>
        /// Creates a <see cref="FlowScript"/> from a <see cref="FlowScriptBinary"/> object.
        /// </summary>
        /// <param name="binary">A <see cref="FlowScriptBinary"/> instance.</param>
        /// <returns>A <see cref="FlowScript"/> instance.</returns>
        public static FlowScript FromBinary( FlowScriptBinary binary, Encoding encoding = null )
        {
            var instance = new FlowScript
            {
                mUserId = binary.Header.UserId
            };

            // assign labels later after convert the instructions because we need to update the instruction indices
            // to reference the instructions in the list, and not the instructions in the array of instructions in the binary

            // assign strings before instructions so we can assign proper string indices as we convert the instructions
            var stringBinaryIndexToListIndexMap = new Dictionary<short, short>();
            var strings = new List<string>();

            if ( binary.StringSection != null )
            {
                short curStringBinaryIndex = 0;
                var curStringBytes = new List<byte>();

                for ( short i = 0; i < binary.StringSection.Count; i++ )
                {
                    // check for string terminator or end of string section
                    if ( binary.StringSection[i] == 0 || i + 1 == binary.StringSection.Count )
                    {
                        strings.Add( ShiftJISEncoding.Instance.GetString( curStringBytes.ToArray() ) );
                        stringBinaryIndexToListIndexMap[curStringBinaryIndex] = ( short )( strings.Count - 1 );

                        // next string will start at the next byte if there are any left
                        curStringBinaryIndex = ( short )( i + 1 );
                        curStringBytes = new List<byte>();
                    }
                    else
                    {
                        curStringBytes.Add( binary.StringSection[ i ] );
                    }
                }
            }

            var instructionBinaryIndexToListIndexMap = new Dictionary<int, int>();
            var instructions = new List<Instruction>();

            // assign instructions
            // TODO: optimize this away later as i don't feel like it right now
            if ( binary.TextSection != null )
            {
                int instructionIndex = 0;
                int instructionBinaryIndex = 0;

                while ( instructionBinaryIndex < binary.TextSection.Count )
                {               
                    // Convert each instruction
                    var binaryInstruction = binary.TextSection[instructionBinaryIndex];

                    Instruction instruction;

                    // Handle instructions we need to alter seperately
                    if ( binaryInstruction.Opcode == Opcode.PUSHSTR )
                    {
                        // Update the string offset to reference the strings inside of the string list
                        instruction = Instruction.PUSHSTR( strings[stringBinaryIndexToListIndexMap[binaryInstruction.OperandShort]] );
                    }
                    else if ( binaryInstruction.Opcode == Opcode.PUSHI )
                    {
                        instruction = Instruction.PUSHI( binary.TextSection[instructionBinaryIndex + 1].OperandInt );
                    }
                    else if ( binaryInstruction.Opcode == Opcode.PUSHF )
                    {
                        instruction = Instruction.PUSHF( binary.TextSection[instructionBinaryIndex + 1].OperandFloat );
                    }
                    else
                    {
                        instruction = Instruction.FromBinaryInstruction( binaryInstruction );
                    }

                    // Add to list
                    instructions.Add( instruction );
                    instructionBinaryIndexToListIndexMap[instructionBinaryIndex] = instructionIndex++;

                    // Increment the instruction binary index by 2 if the current instruction takes up 2 instructions
                    if ( instruction.UsesTwoBinaryInstructions )
                        instructionBinaryIndex += 2;
                    else
                        instructionBinaryIndex += 1;
                }
            }

            // assign labels as the instruction index remap table has been built
            var sortedProcedureLabels = binary.ProcedureLabelSection.OrderBy( x => x.InstructionIndex ).ToList();

            for ( int i = 0; i < binary.ProcedureLabelSection.Count; i++ )
            {
                var procedureLabel = binary.ProcedureLabelSection[ i ];
                int procedureListStartIndex = instructionBinaryIndexToListIndexMap[ procedureLabel.InstructionIndex ];
                int nextProcedureLabelIndex = sortedProcedureLabels.FindIndex( x => x.InstructionIndex == procedureLabel.InstructionIndex ) + 1;
                int procedureInstructionCount;
                int procedureBinaryEndIndex; // inclusive

                // Calculate the number of instructions in the procedure
                bool isLastProcedure = nextProcedureLabelIndex == binary.ProcedureLabelSection.Count;
                if ( isLastProcedure )
                {
                    procedureInstructionCount = ( instructions.Count - procedureListStartIndex );
                    procedureBinaryEndIndex = binary.TextSection.Count - 1;
                }
                else
                {
                    var nextProcedureLabel = binary.ProcedureLabelSection[nextProcedureLabelIndex];
                    procedureInstructionCount = ( instructionBinaryIndexToListIndexMap[nextProcedureLabel.InstructionIndex] - procedureListStartIndex );
                    procedureBinaryEndIndex = nextProcedureLabel.InstructionIndex - 1;
                }

                // Copy the instruction range
                var procedureInstructions = new List<Instruction>( procedureInstructionCount );
                for ( int j = 0; j < procedureInstructionCount; j++ )
                    procedureInstructions.Add( instructions[ procedureListStartIndex + j ] );

                // Create the new procedure representation
                Procedure procedure;

                if ( binary.JumpLabelSection != null )
                {
                    // Find jump labels within instruction range of procedure
                    var procedureBinaryJumpLabels = binary.JumpLabelSection
                        .Where( x => x.InstructionIndex >= procedureLabel.InstructionIndex && x.InstructionIndex <= procedureBinaryEndIndex )
                        .ToList();

                    if ( procedureBinaryJumpLabels.Count > 0 )
                    {
                        // Generate mapping between label name and the procedure-local index of the label
                        var procedureJumpLabelNameToLocalIndexMap = new Dictionary<string, int>( procedureBinaryJumpLabels.Count );

                        for ( int k = 0; k < procedureBinaryJumpLabels.Count; k++ )
                            procedureJumpLabelNameToLocalIndexMap[procedureBinaryJumpLabels[k].Name] = k;

                        // Convert the labels to the new representation
                        var procedureJumpLabels = new List<Label>( procedureBinaryJumpLabels.Count );
                        foreach ( var procedureBinaryJumpLabel in procedureBinaryJumpLabels )
                        {
                            int globalInstructionListIndex = instructionBinaryIndexToListIndexMap[procedureBinaryJumpLabel.InstructionIndex];
                            int localInstructionListIndex = globalInstructionListIndex - procedureListStartIndex;
                            procedureJumpLabels.Add( new Label( procedureBinaryJumpLabel.Name, localInstructionListIndex ) );
                        }

                        // Create the procedure
                        procedure = new Procedure( procedureLabel.Name, procedureInstructions, procedureJumpLabels );

                        // Loop over the instructions and update the instructions that reference labels
                        // so that they refer to the proper procedure-local label index
                        for ( int j = 0; j < procedure.Instructions.Count; j++ )
                        {
                            var instruction = procedure.Instructions[j];
                            if ( instruction.Opcode == Opcode.GOTO || instruction.Opcode == Opcode.IF )
                            {
                                short globalIndex = instruction.Operand.Int16Value;
                                var binaryLabel = binary.JumpLabelSection[globalIndex];

                                short localIndex = ( short )procedureJumpLabelNameToLocalIndexMap[binaryLabel.Name];
                                instruction.Operand.Int16Value = localIndex ;

                                Debug.Assert( procedure.Labels[localIndex].Name == binaryLabel.Name );
                            }

                            procedure.Instructions[j] = instruction;
                        }
                    }
                    else
                    {
                        // Create the procedure
                        procedure = new Procedure( procedureLabel.Name, procedureInstructions );
                    }
                }
                else
                {
                    // Create the procedure
                    procedure = new Procedure( procedureLabel.Name, procedureInstructions );
                }

                instance.mProcedures.Add( procedure );
            }

            // assign message script
            if ( binary.MessageScriptSection != null )
            {
                instance.mMessageScript = MessageScript.FromBinary( binary.MessageScriptSection, MessageScriptLanguage.FormatVersion.Detect, encoding );
            }

            // strings have already been assigned previously, 
            // so last up is the version
            instance.mFormatVersion = (FormatVersion)binary.FormatVersion;

            // everything is assigned, return the constructed instance
            return instance;
        }

        //
        // Instance fields
        //

        private short mUserId;
        private List<Procedure> mProcedures;
        private MessageScript mMessageScript;
        private FormatVersion mFormatVersion;

        /// <summary>
        /// Gets or sets the id metadata field.
        /// </summary>
        public short UserId
        {
            get { return mUserId; }
            set { mUserId = value; }
        }

        /// <summary>
        /// Gets the procedure list.
        /// </summary>
        public List<Procedure> Procedures
        {
            get { return mProcedures; }
        }

        /// <summary>
        /// Gets or sets. the embedded <see cref="MessageScript"/> instance.
        /// </summary>
        public MessageScript MessageScript
        {
            get { return mMessageScript; }
            set { mMessageScript = value; }
        }

        /// <summary>
        /// Gets the binary format version.
        /// </summary>
        public FormatVersion FormatVersion
        {
            get { return mFormatVersion; }
        }

        /// <summary>
        /// Initializes an empty flow script.
        /// </summary>
        private FlowScript()
        {
            mUserId = 0;
            mProcedures = new List<Procedure>();
            mMessageScript = null;
        }

        /// <summary>
        /// Initializes an empty flow script.
        /// </summary>
        public FlowScript( FormatVersion version ) : this()
        {
            mFormatVersion = version;
        }

        /// <summary>
        /// Converts the <see cref="FlowScript"/> to a <see cref="FlowScriptBinary"/> instance.
        /// </summary>
        /// <returns>A <see cref="FlowScriptBinary"/> instance.</returns>
        public FlowScriptBinary ToBinary()
        {
            var builder = new FlowScriptBinaryBuilder( (BinaryFormatVersion)mFormatVersion );
            builder.SetUserId( mUserId );

            // Skip the labels until after the instructions have been converted, as we need to fix up
            // the instruction indices

            // Convert string table before the instructions so we can fix up string instructions later
            // by building an index remap table
            // TODO: optimize instructions usage
            var stringIndexToBinaryStringIndexMap = new Dictionary<short, short>();
            var strings = EnumerateInstructions()
                .Where( x => x.Opcode == Opcode.PUSHSTR )
                .Select( x => x.Operand.StringValue)
                .Distinct()
                .ToList();

            for ( short stringIndex = 0; stringIndex < strings.Count; stringIndex++ )
            {
                builder.AddString( strings[stringIndex], out int binaryIndex );
                stringIndexToBinaryStringIndexMap[stringIndex] = ( short )binaryIndex;
            }

            // Convert procedures
            int instructionBinaryIndex = 0;
            int nextBinaryLabelIndex = 0;

            foreach ( var procedure in mProcedures )
            {
                int procedureInstructionStartBinaryIndex = instructionBinaryIndex;
                var procedureInstructionListIndexToBinaryIndexMap = new Dictionary<int, int>();
                var procedureIndexRemap = new Dictionary<int, int>();

                // Convert instructions in procedure
                for ( int instructionIndex = 0; instructionIndex < procedure.Instructions.Count; instructionIndex++ )
                {
                    procedureInstructionListIndexToBinaryIndexMap[instructionIndex] = instructionBinaryIndex;

                    var instruction = procedure.Instructions[instructionIndex];

                    if ( !instruction.UsesTwoBinaryInstructions )
                    {
                        var binaryInstruction = new BinaryInstruction
                        {
                            Opcode = instruction.Opcode
                        };

                        if ( instruction.Opcode == Opcode.PUSHSTR )
                        {
                            // Handle PUSHSTR seperately due to difference in string index usage
                            short stringIndex = ( short )strings.IndexOf( instruction.Operand.StringValue);
                            if ( stringIndex == -1 )
                                throw new InvalidDataException( "String could not be found??" );

                            binaryInstruction.OperandShort = stringIndexToBinaryStringIndexMap[stringIndex];
                        }
                        else if ( instruction.Opcode == Opcode.GOTO || instruction.Opcode == Opcode.IF )
                        {
                            // Convert procedure-local label index to global label index
                            int oldIndex = instruction.Operand.Int16Value;
                            if ( !procedureIndexRemap.ContainsKey( oldIndex ))
                            {
                                procedureIndexRemap[oldIndex] = nextBinaryLabelIndex++;
                            }

                            binaryInstruction.OperandShort = (short)procedureIndexRemap[oldIndex];
                        }
                        else
                        {
                            // Handle regular instruction
                            if ( instruction.Operand != null )
                                binaryInstruction.OperandShort = instruction.Operand.Int16Value;
                        }

                        builder.AddInstruction( binaryInstruction );
                        instructionBinaryIndex += 1;
                    }
                    else
                    {
                        // Handle instruction that uses the next instruction as its operand
                        var binaryInstruction = new BinaryInstruction { Opcode = instruction.Opcode };
                        var binaryInstruction2 = new BinaryInstruction();

                        switch ( instruction.Operand.Kind )
                        {
                            case Operand.ValueKind.Int32:
                                binaryInstruction2.OperandInt = instruction.Operand.Int32Value;
                                break;
                            case Operand.ValueKind.Single:
                                binaryInstruction2.OperandFloat = instruction.Operand.SingleValue;
                                break;
                            default:
                                throw new InvalidOperationException();
                        }

                        builder.AddInstruction( binaryInstruction );
                        builder.AddInstruction( binaryInstruction2 );
                        instructionBinaryIndex += 2;
                    }
                }

                // Convert labels in procedure after the instructions to remap the instruction indices
                foreach ( var key in procedureIndexRemap.Keys )
                {
                    var label = procedure.Labels[key];
                    builder.AddJumpLabel( new BinaryLabel { InstructionIndex = procedureInstructionListIndexToBinaryIndexMap[label.InstructionIndex], Name = label.Name, Reserved = 0 } );
                }

                // Add procedure to builder
                builder.AddProcedureLabel( new BinaryLabel { InstructionIndex = procedureInstructionStartBinaryIndex, Name = procedure.Name, Reserved = 0 } );
            }

            // Convert message script
            if ( mMessageScript != null )
                builder.SetMessageScriptSection( mMessageScript );

            return builder.Build();
        }

        /// <summary>
        /// Serializes the <see cref="FlowScript"/> instance to the specified file.
        /// </summary>
        /// <param name="path">The output file path.</param>
        public void ToFile( string path )
        {
            if ( path == null )
                throw new ArgumentNullException( nameof( path ) );

            if ( string.IsNullOrEmpty( path ) )
                throw new ArgumentException( "Value cannot be null or empty.", nameof( path ) );

            using ( var stream = FileUtils.Create( path ) )
                ToStream( stream );
        }

        /// <summary>
        /// Serializes the <see cref="FlowScript"/> instance to a stream.
        /// </summary>
        /// <returns>A formatted stream.</returns>
        public Stream ToStream()
        {
            var stream = new MemoryStream();
            ToStream( stream, true );
            return stream;
        }

        /// <summary>
        /// Serializes the <see cref="FlowScript"/> instance to a specified stream.
        /// </summary>
        /// <param name="stream">The stream to serialize to.</param>
        /// <param name="leaveOpen">Indicates whether the specified stream should be left open.</param>
        public void ToStream( Stream stream, bool leaveOpen = false )
        {
            var binary = ToBinary();
            binary.ToStream( stream, leaveOpen );
        }

        /// <summary>
        /// Enumerates over all of the instructions in the script.
        /// </summary>
        /// <returns></returns>
        public IEnumerable<Instruction> EnumerateInstructions() => Procedures.SelectMany( x => x.Instructions );
    }
}
