using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AtlusScriptLib.BinaryModel;

namespace AtlusScriptLib
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
        public static FlowScript FromFile( string path )
        {
            return FromFile( path, FlowScriptBinaryFormatVersion.Unknown );
        }

        /// <summary>
        /// Creates a <see cref="FlowScript"/> by loading it from a file in the specified format version.
        /// </summary>
        /// <param name="path">Path to the file to load.</param>
        /// <param name="version">Format version the loader should use.</param>
        /// <returns>A <see cref="FlowScript"/> instance.</returns>
        public static FlowScript FromFile( string path, FlowScriptBinaryFormatVersion version )
        {
            using ( var stream = File.OpenRead( path ) )
                return FromStream( stream, version );
        }

        /// <summary>
        /// Creates a <see cref="FlowScript"/> by loading it from a stream.
        /// </summary>
        /// <param name="stream">Data stream.</param>
        /// <param name="version">Format version the loader should use.</param>
        /// <returns>A <see cref="FlowScript"/> instance.</returns>
        public static FlowScript FromStream( Stream stream, bool leaveOpen = false )
        {
            return FromStream( stream, FlowScriptBinaryFormatVersion.Unknown );
        }

        /// <summary>
        /// Creates a <see cref="FlowScript"/> by loading it from a stream in the specified format version.
        /// </summary>
        /// <param name="stream">Data stream.</param>
        /// <param name="version">Format version the loader should use.</param>
        /// <returns>A <see cref="FlowScript"/> instance.</returns>
        public static FlowScript FromStream( Stream stream, FlowScriptBinaryFormatVersion version, bool leaveOpen = false )
        {
            FlowScriptBinary binary = FlowScriptBinary.FromStream( stream, version, leaveOpen );

            return FromBinary( binary );
        }

        /// <summary>
        /// Creates a <see cref="FlowScript"/> from a <see cref="FlowScriptBinary"/> object.
        /// </summary>
        /// <param name="binary">A <see cref="FlowScriptBinary"/> instance.</param>
        /// <returns>A <see cref="FlowScript"/> instance.</returns>
        public static FlowScript FromBinary( FlowScriptBinary binary )
        {
            var instance = new FlowScript()
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
                string curString = string.Empty;

                for ( short i = 0; i < binary.StringSection.Count; i++ )
                {
                    // check for string terminator or end of string section
                    if ( binary.StringSection[i] == 0 || i + 1 == binary.StringSection.Count )
                    {
                        strings.Add( curString );
                        stringBinaryIndexToListIndexMap[curStringBinaryIndex] = ( short )( strings.Count - 1 );

                        // next string will start at the next byte if there are any left
                        curStringBinaryIndex = ( short )( i + 1 );
                        curString = string.Empty;
                    }
                    else
                    {
                        curString += ( char )binary.StringSection[i];
                    }
                }
            }

            var instructionBinaryIndexToListIndexMap = new Dictionary<int, int>();

            // assign instructions
            if ( binary.TextSection != null )
            {
                int instructionIndex = 0;
                int instructionBinaryIndex = 0;

                while ( instructionBinaryIndex < binary.TextSection.Count )
                {
                    instructionBinaryIndexToListIndexMap[instructionBinaryIndex] = instructionIndex;

                    // Convert each instruction
                    var binaryInstruction = binary.TextSection[instructionBinaryIndex];

                    FlowScriptInstruction instruction;

                    // Handle instructions we need to alter seperately
                    if ( binaryInstruction.Opcode == FlowScriptOpcode.PUSHSTR )
                    {
                        // Update the string offset to reference the strings inside of the string list
                        instruction = FlowScriptInstruction.PUSHSTR( strings[stringBinaryIndexToListIndexMap[binaryInstruction.OperandShort]] );
                    }
                    else if ( binaryInstruction.Opcode == FlowScriptOpcode.PUSHI )
                    {
                        instruction = FlowScriptInstruction.PUSHI( binary.TextSection[instructionBinaryIndex + 1].OperandInt );
                    }
                    else if ( binaryInstruction.Opcode == FlowScriptOpcode.PUSHF )
                    {
                        instruction = FlowScriptInstruction.PUSHF( binary.TextSection[instructionBinaryIndex + 1].OperandFloat );
                    }
                    else
                    {
                        instruction = FlowScriptInstruction.FromBinaryInstruction( binaryInstruction );
                    }

                    // Add to list
                    instance.mInstructions.Add( instruction );
                    instructionIndex++;

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
                var label = binary.ProcedureLabelSection[i];
                int startIndex = instructionBinaryIndexToListIndexMap[label.InstructionIndex];

                int nextLabelIndex = sortedProcedureLabels.FindIndex( x => x.InstructionIndex == label.InstructionIndex ) + 1;
                int count;

                bool isLast = nextLabelIndex == binary.ProcedureLabelSection.Count;
                if ( isLast )
                {
                    count = ( instance.mInstructions.Count - startIndex );
                }
                else
                {
                    var nextLabel = binary.ProcedureLabelSection[nextLabelIndex];
                    count = ( instructionBinaryIndexToListIndexMap[nextLabel.InstructionIndex] - startIndex );
                }

                var instructions = new List<FlowScriptInstruction>( count );
                for ( int j = 0; j < count; j++ )
                    instructions.Add( instance.mInstructions[ startIndex + j ] );

                var procedure = new FlowScriptProcedure( label.Name, instructions );

                instance.mProcedures.Add( procedure );
            }

            if ( binary.JumpLabelSection != null )
            {
                foreach ( var label in binary.JumpLabelSection )
                {
                    instance.mJumpLabels.Add( new FlowScriptLabel( label.Name,
                        instructionBinaryIndexToListIndexMap[label.InstructionIndex] ) );
                }
            }

            // assign message script
            if ( binary.MessageScriptSection != null )
            {
                instance.mMessageScript = MessageScript.FromBinary( binary.MessageScriptSection );
            }

            // strings have already been assigned previously, 
            // so last up is the version
            instance.mFormatVersion = binary.FormatVersion;

            // everything is assigned, return the constructed instance
            return instance;
        }

        //
        // Instance fields
        //

        private short mUserId;
        private List<FlowScriptProcedure> mProcedures;
        private List<FlowScriptLabel> mJumpLabels;
        private List<FlowScriptInstruction> mInstructions;
        private MessageScript mMessageScript;
        private FlowScriptBinaryFormatVersion mFormatVersion;

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
        public List<FlowScriptProcedure> Procedures
        {
            get { return mProcedures; }
        }

        /// <summary>
        /// Gets the jump label list.
        /// </summary>
        public List<FlowScriptLabel> JumpLabels
        {
            get { return mJumpLabels; }
        }

        /// <summary>
        /// Gets the instruction list.
        /// </summary>
        public List<FlowScriptInstruction> Instructions
        {
            get { return mInstructions; }
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
        public FlowScriptBinaryFormatVersion FormatVersion
        {
            get { return mFormatVersion; }
        }

        /// <summary>
        /// Initializes an empty flow script.
        /// </summary>
        private FlowScript()
        {
            mUserId = 0;
            mProcedures = new List<FlowScriptProcedure>();
            mJumpLabels = new List<FlowScriptLabel>();
            mInstructions = new List<FlowScriptInstruction>();
            mMessageScript = null;
            mFormatVersion = FlowScriptBinaryFormatVersion.Unknown;
        }

        /// <summary>
        /// Converts the <see cref="FlowScript"/> to a <see cref="FlowScriptBinary"/> instance.
        /// </summary>
        /// <returns>A <see cref="FlowScriptBinary"/> instance.</returns>
        public FlowScriptBinary ToBinary()
        {
            var builder = new FlowScriptBinaryBuilder( mFormatVersion );
            builder.SetUserId( mUserId );

            // Skip the labels until after the instructions have been converted, as we need to fix up
            // the instruction indices

            // Convert string table before the instructions so we can fix up string instructions later
            // by building an index remap table
            var stringIndexToBinaryStringIndexMap = new Dictionary<short, short>();
            var strings = mInstructions
                .Where( x => x.Opcode == FlowScriptOpcode.PUSHSTR )
                .Select( x => x.Operand.GetStringValue() )
                .Distinct()
                .ToList();

            if ( mInstructions.Count > 0 )
            {
                for ( short stringIndex = 0; stringIndex < strings.Count; stringIndex++ )
                {
                    builder.AddString( strings[stringIndex], out int binaryIndex );
                    stringIndexToBinaryStringIndexMap[stringIndex] = ( short )binaryIndex;
                }
            }

            // Convert instructions, build an instruction index remap table & remap string indices where necessary
            int instructionListIndex = 0;
            int instructionBinaryIndex = 0;
            var instructionListIndexToBinaryIndexMap = new Dictionary<int, int>();
            var procedureToBinaryIndexMap = new Dictionary<string, int>();

            foreach ( var procedure in mProcedures )
            {
                procedureToBinaryIndexMap[procedure.Name] = instructionBinaryIndex;

                for ( int instructionIndex = 0; instructionIndex < procedure.Instructions.Count; instructionIndex++ )
                {
                    instructionListIndexToBinaryIndexMap[instructionListIndex++] = instructionBinaryIndex;

                    var instruction = procedure.Instructions[instructionIndex];

                    if ( !instruction.UsesTwoBinaryInstructions )
                    {
                        var binaryInstruction = new FlowScriptBinaryInstruction()
                        {
                            Opcode = instruction.Opcode
                        };

                        // Handle PUSHSTR seperately due to difference in string index usage
                        if ( instruction.Opcode == FlowScriptOpcode.PUSHSTR )
                        {
                            short stringIndex = ( short )strings.IndexOf( instruction.Operand.GetStringValue() );
                            if ( stringIndex == -1 )
                                throw new InvalidDataException( "String could not be found??" );

                            binaryInstruction.OperandShort = stringIndexToBinaryStringIndexMap[stringIndex];
                        }
                        else
                        {
                            // Handle regular instruction
                            if ( instruction.Operand != null )
                                binaryInstruction.OperandShort = instruction.Operand.GetInt16Value();
                        }

                        builder.AddInstruction( binaryInstruction );
                        instructionBinaryIndex += 1;
                    }
                    else
                    {
                        // Handle instruction that uses the next instruction as its operand
                        var binaryInstruction = new FlowScriptBinaryInstruction() { Opcode = instruction.Opcode };
                        var binaryInstruction2 = new FlowScriptBinaryInstruction();

                        switch ( instruction.Operand.Type )
                        {
                            case FlowScriptInstruction.OperandValue.ValueType.Int32:
                                binaryInstruction2.OperandInt = instruction.Operand.GetInt32Value();
                                break;
                            case FlowScriptInstruction.OperandValue.ValueType.Single:
                                binaryInstruction2.OperandFloat = instruction.Operand.GetSingleValue();
                                break;
                            default:
                                throw new InvalidOperationException();
                        }

                        builder.AddInstruction( binaryInstruction );
                        builder.AddInstruction( binaryInstruction2 );
                        instructionBinaryIndex += 2;
                    }
                }
            }

            // Convert labels after the instructions to remap the instruction indices
            foreach ( var procedure in mProcedures )
            {
                builder.AddProcedureLabel( new FlowScriptBinaryLabel { InstructionIndex = procedureToBinaryIndexMap[procedure.Name], Name = procedure.Name, Reserved = 0 } );
            }

            foreach ( var label in mJumpLabels )
            {
                builder.AddJumpLabel( new FlowScriptBinaryLabel { InstructionIndex = instructionListIndexToBinaryIndexMap[label.InstructionIndex], Name = label.Name, Reserved = 0 } );
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

            using ( var stream = File.Create( path ) )
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
    }
}
