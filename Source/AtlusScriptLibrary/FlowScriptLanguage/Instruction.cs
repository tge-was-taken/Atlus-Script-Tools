using System;
using AtlusScriptLibrary.FlowScriptLanguage.BinaryModel;

// ReSharper disable InconsistentNaming

namespace AtlusScriptLibrary.FlowScriptLanguage
{
    /// <summary>
    /// Represents a single instruction in a <see cref="FlowScript"/>.
    /// </summary>
    public class Instruction : IEquatable<Instruction>
    {
        /// <summary>
        /// Gets the opcode of this instruction.
        /// </summary>
        public Opcode Opcode { get; }

        /// <summary>
        /// Gets the operand of this instruction. Returned value is null if no operand is present.
        /// </summary>
        public Operand Operand { get; }

        /// <summary>
        /// Gets if this instruction takes up two instructions when converted to its binary representation.
        /// </summary>
        public bool UsesTwoBinaryInstructions => Opcode == Opcode.PUSHI || Opcode == Opcode.PUSHF;

        /// <summary>
        /// Constructs a new instruction with a specified opcode with no operand.
        /// </summary>
        /// <param name="opcode">The opcode of the instruction.</param>
        private Instruction( Opcode opcode )
        {
            Opcode = opcode;
            Operand = null;
        }

        /// <summary>
        /// Constructs a new instruction with a specified opcode with a short operand.
        /// </summary>
        /// <param name="opcode">The opcode of the instruction.</param>
        /// <param name="value">The operand value.</param>
        private Instruction( Opcode opcode, short value )
        {
            Opcode = opcode;
            Operand = new Operand( value );
        }

        /// <summary>
        /// Constructs a new instruction with a specified opcode with an int operand.
        /// </summary>
        /// <param name="opcode">The opcode of the instruction.</param>
        /// <param name="value">The operand value.</param>
        private Instruction( Opcode opcode, int value )
        {
            Opcode = opcode;
            Operand = new Operand( value );
        }

        /// <summary>
        /// Constructs a new instruction with a specified opcode with a float operand.
        /// </summary>
        /// <param name="opcode">The opcode of the instruction.</param>
        /// <param name="value">The operand value.</param>
        private Instruction( Opcode opcode, float value )
        {
            Opcode = opcode;
            Operand = new Operand( value );
        }

        /// <summary>
        /// Constructs a new instruction with a specified opcode with a string operand.
        /// </summary>
        /// <param name="opcode">The opcode of the instruction.</param>
        /// <param name="value">The operand value.</param>
        private Instruction( Opcode opcode, string value )
        {
            Opcode = opcode;
            Operand = new Operand( value );
        }

        /// <summary>
        /// Converts a binary instruction to its simplified representation. 
        /// This method is only valid for instructions that don't take up 2 instructions.
        /// </summary>
        /// <param name="binary">The binary instruction.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction FromBinaryInstruction( BinaryInstruction binary )
        {
            switch ( binary.Opcode )
            {
                case Opcode.PUSHIX:
                    return PUSHIX( binary.OperandShort );

                case Opcode.PUSHIF:
                    return PUSHIF( binary.OperandShort );

                case Opcode.PUSHREG:
                    return PUSHREG();

                case Opcode.POPIX:
                    return POPIX( binary.OperandShort );

                case Opcode.POPFX:
                    return POPFX( binary.OperandShort );

                case Opcode.PROC:
                    return PROC( binary.OperandShort );

                case Opcode.COMM:
                    return COMM( binary.OperandShort );

                case Opcode.END:
                    return END();

                case Opcode.JUMP:
                    return JUMP( binary.OperandShort );

                case Opcode.CALL:
                    return CALL( binary.OperandShort );

                case Opcode.RUN:
                    return RUN();

                case Opcode.GOTO:
                    return GOTO( binary.OperandShort );

                case Opcode.ADD:
                    return ADD();

                case Opcode.SUB:
                    return SUB();

                case Opcode.MUL:
                    return MUL();

                case Opcode.DIV:
                    return DIV();

                case Opcode.MINUS:
                    return MINUS();

                case Opcode.NOT:
                    return NOT();

                case Opcode.OR:
                    return OR();

                case Opcode.AND:
                    return AND();

                case Opcode.EQ:
                    return EQ();

                case Opcode.NEQ:
                    return NEQ();

                case Opcode.S:
                    return S();

                case Opcode.L:
                    return L();

                case Opcode.SE:
                    return SE();

                case Opcode.LE:
                    return LE();

                case Opcode.IF:
                    return IF( binary.OperandShort );

                case Opcode.PUSHIS:
                    return PUSHIS( binary.OperandShort );

                case Opcode.PUSHLIX:
                    return PUSHLIX( binary.OperandShort );

                case Opcode.PUSHLFX:
                    return PUSHLFX( binary.OperandShort );

                case Opcode.POPLIX:
                    return POPLIX( binary.OperandShort );

                case Opcode.POPLFX:
                    return POPLFX( binary.OperandShort );

                default:
                    throw new Exception( "Opcode not supported" );
            }
        }

        /// <summary>
        /// Creates a PUSHI (push integer) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction PUSHI( int value )
        {
            return new Instruction( Opcode.PUSHI, value );
        }

        /// <summary>
        /// Creates a PUSHF (push float) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction PUSHF( float value )
        {
            return new Instruction( Opcode.PUSHF, value );
        }

        /// <summary>
        /// Creates a PUSHIX (push global indexed int) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction PUSHIX( short globalIntVariableIndex )
        {
            return new Instruction( Opcode.PUSHIX, globalIntVariableIndex );
        }

        /// <summary>
        /// Creates a PUSHF (push global indexed float) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction PUSHIF( short globalFloatVariableIndex )
        {
            return new Instruction( Opcode.PUSHIF, globalFloatVariableIndex );
        }

        /// <summary>
        /// Creates a PUSHREG (push register) instruction.
        /// </summary>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction PUSHREG()
        {
            return new Instruction( Opcode.PUSHREG );
        }

        /// <summary>
        /// Creates a POPIX (pop global indexed int) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction POPIX( short globalIntVariableIndex )
        {
            return new Instruction( Opcode.POPIX, globalIntVariableIndex );
        }

        /// <summary>
        /// Creates a POPFX (pop global indexed float) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction POPFX( short globalFloatVariableIndex )
        {
            return new Instruction( Opcode.POPFX, globalFloatVariableIndex );
        }

        /// <summary>
        /// Creates a PROC (procedure) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction PROC( short procedureIndex )
        {
            return new Instruction( Opcode.PROC, procedureIndex );
        }

        /// <summary>
        /// Creates a COMM (communicate) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction COMM( short functionId )
        {
            return new Instruction( Opcode.COMM, functionId );
        }

        /// <summary>
        /// Creates a END (end procedure) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction END()
        {
            return new Instruction( Opcode.END );
        }

        /// <summary>
        /// Creates a JUMP (jump to procedure) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction JUMP( short procedureLabelIndex )
        {
            return new Instruction( Opcode.JUMP, procedureLabelIndex );
        }

        /// <summary>
        /// Creates a CALL (call procedure) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction CALL( short procedureLabelIndex )
        {
            return new Instruction( Opcode.CALL, procedureLabelIndex );
        }

        /// <summary>
        /// Creates a RUN (run script) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction RUN()
        {
            return new Instruction( Opcode.RUN );
        }

        /// <summary>
        /// Creates a GOTO (go to label) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction GOTO( short jumpLabelIndex )
        {
            return new Instruction( Opcode.GOTO, jumpLabelIndex );
        }

        /// <summary>
        /// Creates an ADD (add) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction ADD()
        {
            return new Instruction( Opcode.ADD );
        }

        /// <summary>
        /// Creates a SUB (subtract) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction SUB()
        {
            return new Instruction( Opcode.SUB );
        }

        /// <summary>
        /// Creates a MUL (multiply) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction MUL()
        {
            return new Instruction( Opcode.MUL );
        }

        /// <summary>
        /// Creates a DIV (divide) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction DIV()
        {
            return new Instruction( Opcode.DIV );
        }

        /// <summary>
        /// Creates a MINUS (minus) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction MINUS()
        {
            return new Instruction( Opcode.MINUS );
        }

        /// <summary>
        /// Creates a NOT (bitwise not) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction NOT()
        {
            return new Instruction( Opcode.NOT );
        }

        /// <summary>
        /// Creates a OR (bitwise or) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction OR()
        {
            return new Instruction( Opcode.OR );
        }

        /// <summary>
        /// Creates an AND (bitwise and) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction AND()
        {
            return new Instruction( Opcode.AND );
        }

        /// <summary>
        /// Creates a EQ (equality) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction EQ()
        {
            return new Instruction( Opcode.EQ );
        }

        /// <summary>
        /// Creates a NEQ (non-equality) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction NEQ()
        {
            return new Instruction( Opcode.NEQ );
        }

        /// <summary>
        /// Creates a S (smaller, less than) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction S()
        {
            return new Instruction( Opcode.S );
        }

        /// <summary>
        /// Creates a L (larger, more than) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction L()
        {
            return new Instruction( Opcode.L );
        }

        /// <summary>
        /// Creates a SE (smaller or equal, less than or equal) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction SE()
        {
            return new Instruction( Opcode.SE );
        }

        /// <summary>
        /// Creates a LE (larger or equal, more than or equal) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction LE()
        {
            return new Instruction( Opcode.LE );
        }

        /// <summary>
        /// Creates a IF (logical if) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction IF( short jumpLabelIndexIfFalse )
        {
            return new Instruction( Opcode.IF, jumpLabelIndexIfFalse );
        }

        /// <summary>
        /// Creates a PUSHIS (push immediate short) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction PUSHIS( short value )
        {
            return new Instruction( Opcode.PUSHIS, value );
        }

        /// <summary>
        /// Creates a PUSHLIX (push local indexed int) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction PUSHLIX( short localIntVariableIndex )
        {
            return new Instruction( Opcode.PUSHLIX, localIntVariableIndex );
        }

        /// <summary>
        /// Creates a PUSHLFX (push local indexed float) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction PUSHLFX( short localFloatVariableIndex )
        {
            return new Instruction( Opcode.PUSHLFX, localFloatVariableIndex );
        }

        /// <summary>
        /// Creates a POPLIX (pop local indexed int) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction POPLIX( short localIntVariableIndex )
        {
            return new Instruction( Opcode.POPLIX, localIntVariableIndex );
        }

        /// <summary>
        /// Creates a POPLFX (pop local indexed float) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction POPLFX( short localFloatVariableIndex )
        {
            return new Instruction( Opcode.POPLFX, localFloatVariableIndex );
        }

        /// <summary>
        /// Creates a PUSHSTR (push string) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="Instruction"/> instance.</returns>
        public static Instruction PUSHSTR( string value )
        {
            return new Instruction( Opcode.PUSHSTR, value );
        }

        public override string ToString()
        {
            return $"{Opcode} {Operand}";
        }

        public bool Equals(Instruction other)
        {
            return Opcode == other.Opcode && (Operand == other.Operand || Operand.Equals(other.Operand));
        }
    }
}
