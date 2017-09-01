using System;
using AtlusScriptLib.BinaryModel;

namespace AtlusScriptLib
{
    /// <summary>
    /// Represents a single instruction in a <see cref="FlowScript"/>.
    /// </summary>
    public class FlowScriptInstruction
    {
        private FlowScriptOpcode mOpcode;
        private OperandValue mOperand;

        /// <summary>
        /// Gets the opcode of this instruction.
        /// </summary>
        public FlowScriptOpcode Opcode
        {
            get { return mOpcode; }
        }

        /// <summary>
        /// Gets the operand of this instruction. Returned value is null if no operand is present.
        /// </summary>
        public OperandValue Operand
        {
            get { return mOperand; }
        }

        /// <summary>
        /// Gets if this instruction takes up two instructions when converted to its binary representation.
        /// </summary>
        public bool UsesTwoBinaryInstructions
        {
            get { return mOpcode == FlowScriptOpcode.PUSHI || mOpcode == FlowScriptOpcode.PUSHF; }
        }

        /// <summary>
        /// Constructs a new instruction with a specified opcode with no operand.
        /// </summary>
        /// <param name="opcode">The opcode of the instruction.</param>
        private FlowScriptInstruction(FlowScriptOpcode opcode)
        {
            mOpcode = opcode;
            mOperand = null;
        }

        /// <summary>
        /// Constructs a new instruction with a specified opcode with a short operand.
        /// </summary>
        /// <param name="opcode">The opcode of the instruction.</param>
        /// <param name="value">The operand value.</param>
        private FlowScriptInstruction(FlowScriptOpcode opcode, short value)
        {
            mOpcode = opcode;
            mOperand = new OperandValue(value);
        }

        /// <summary>
        /// Constructs a new instruction with a specified opcode with an int operand.
        /// </summary>
        /// <param name="opcode">The opcode of the instruction.</param>
        /// <param name="value">The operand value.</param>
        private FlowScriptInstruction(FlowScriptOpcode opcode, int value)
        {
            mOpcode = opcode;
            mOperand = new OperandValue(value);
        }

        /// <summary>
        /// Constructs a new instruction with a specified opcode with a float operand.
        /// </summary>
        /// <param name="opcode">The opcode of the instruction.</param>
        /// <param name="value">The operand value.</param>
        private FlowScriptInstruction(FlowScriptOpcode opcode, float value)
        {
            mOpcode = opcode;
            mOperand = new OperandValue(value);
        }

        /// <summary>
        /// Converts a binary instruction to its simplified representation. 
        /// This method is only valid for instructions that don't take up 2 instructions.
        /// </summary>
        /// <param name="binary">The binary instruction.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction FromBinaryInstruction(FlowScriptBinaryInstruction binary)
        {
            switch (binary.Opcode)
            {
                case FlowScriptOpcode.PUSHIX:
                    return PUSHIX(binary.OperandShort);

                case FlowScriptOpcode.PUSHIF:
                    return PUSHIF(binary.OperandShort);

                case FlowScriptOpcode.PUSHREG:
                    return PUSHREG();

                case FlowScriptOpcode.POPIX:
                    return POPIX(binary.OperandShort);

                case FlowScriptOpcode.POPFX:
                    return POPFX(binary.OperandShort);

                case FlowScriptOpcode.PROC:
                    return PROC(binary.OperandShort);

                case FlowScriptOpcode.COMM:
                    return COMM(binary.OperandShort);

                case FlowScriptOpcode.END:
                    return END();

                case FlowScriptOpcode.JUMP:
                    return JUMP(binary.OperandShort);

                case FlowScriptOpcode.CALL:
                    return CALL(binary.OperandShort);

                case FlowScriptOpcode.RUN:
                    return RUN();

                case FlowScriptOpcode.GOTO:
                    return GOTO(binary.OperandShort);

                case FlowScriptOpcode.ADD:
                    return ADD();

                case FlowScriptOpcode.SUB:
                    return SUB();

                case FlowScriptOpcode.MUL:
                    return MUL();

                case FlowScriptOpcode.DIV:
                    return DIV();

                case FlowScriptOpcode.MINUS:
                    return MINUS();

                case FlowScriptOpcode.NOT:
                    return NOT();

                case FlowScriptOpcode.OR:
                    return OR();

                case FlowScriptOpcode.AND:
                    return AND();

                case FlowScriptOpcode.EQ:
                    return EQ();

                case FlowScriptOpcode.NEQ:
                    return NEQ();

                case FlowScriptOpcode.S:
                    return S();

                case FlowScriptOpcode.L:
                    return L();

                case FlowScriptOpcode.SE:
                    return SE();

                case FlowScriptOpcode.LE:
                    return LE();

                case FlowScriptOpcode.IF:
                    return IF(binary.OperandShort);

                case FlowScriptOpcode.PUSHIS:
                    return PUSHIS(binary.OperandShort);

                case FlowScriptOpcode.PUSHLIX:
                    return PUSHLIX(binary.OperandShort);

                case FlowScriptOpcode.PUSHLFX:
                    return PUSHLFX(binary.OperandShort);

                case FlowScriptOpcode.POPLIX:
                    return POPLIX(binary.OperandShort);

                case FlowScriptOpcode.POPLFX:
                    return POPLFX(binary.OperandShort);

                case FlowScriptOpcode.PUSHSTR:
                    return PUSHSTR(binary.OperandShort);

                default:
                    throw new Exception("Opcode not supported");
            }
        }

        /// <summary>
        /// Creates a PUSHI (push integer) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction PUSHI(int value)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHI, value);
        }

        /// <summary>
        /// Creates a PUSHF (push float) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction PUSHF(float value)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHF, value);
        }

        /// <summary>
        /// Creates a PUSHIX (push global indexed int) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction PUSHIX(short globalIntVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHIX, globalIntVariableIndex);
        }

        /// <summary>
        /// Creates a PUSHF (push global indexed float) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction PUSHIF(short globalFloatVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHIF, globalFloatVariableIndex);
        }

        /// <summary>
        /// Creates a PUSHREG (push register) instruction.
        /// </summary>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction PUSHREG()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHREG);
        }

        /// <summary>
        /// Creates a POPIX (pop global indexed int) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction POPIX(short globalIntVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.POPIX, globalIntVariableIndex);
        }

        /// <summary>
        /// Creates a POPFX (pop global indexed float) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction POPFX(short globalFloatVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.POPFX, globalFloatVariableIndex);
        }

        /// <summary>
        /// Creates a PROC (procedure) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction PROC(short procedureIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PROC, procedureIndex);
        }

        /// <summary>
        /// Creates a COMM (communicate) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction COMM(short functionId)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.COMM, functionId);
        }

        /// <summary>
        /// Creates a END (end procedure) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction END()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.END);
        }

        /// <summary>
        /// Creates a JUMP (jump to procedure) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction JUMP(short procedureLabelIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.JUMP, procedureLabelIndex);
        }

        /// <summary>
        /// Creates a CALL (call procedure) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction CALL(short procedureLabelIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.CALL, procedureLabelIndex);
        }

        /// <summary>
        /// Creates a RUN (run script) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction RUN()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.RUN);
        }

        /// <summary>
        /// Creates a GOTO (go to label) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction GOTO(short jumpLabelIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.GOTO, jumpLabelIndex);
        }

        /// <summary>
        /// Creates an ADD (add) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction ADD()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.ADD);
        }

        /// <summary>
        /// Creates a SUB (subtract) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction SUB()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.SUB);
        }

        /// <summary>
        /// Creates a MUL (multiply) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction MUL()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.MUL);
        }

        /// <summary>
        /// Creates a DIV (divide) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction DIV()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.DIV);
        }

        /// <summary>
        /// Creates a MINUS (minus) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction MINUS()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.MINUS);
        }

        /// <summary>
        /// Creates a NOT (bitwise not) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction NOT()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.NOT);
        }

        /// <summary>
        /// Creates a OR (bitwise or) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction OR()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.OR);
        }

        /// <summary>
        /// Creates an AND (bitwise and) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction AND()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.AND);
        }

        /// <summary>
        /// Creates a EQ (equality) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction EQ()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.EQ);
        }

        /// <summary>
        /// Creates a NEQ (non-equality) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction NEQ()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.NEQ);
        }

        /// <summary>
        /// Creates a S (smaller, less than) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction S()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.S);
        }

        /// <summary>
        /// Creates a L (larger, more than) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction L()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.L);
        }

        /// <summary>
        /// Creates a SE (smaller or equal, less than or equal) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction SE()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.SE);
        }

        /// <summary>
        /// Creates a LE (larger or equal, more than or equal) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction LE()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.LE);
        }

        /// <summary>
        /// Creates a IF (logical if) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction IF(short jumpLabelIndexIfFalse)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.IF, jumpLabelIndexIfFalse);
        }

        /// <summary>
        /// Creates a PUSHIS (push immediate short) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction PUSHIS(short value)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHIS, value);
        }

        /// <summary>
        /// Creates a PUSHLIX (push local indexed int) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction PUSHLIX(short localIntVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHLIX, localIntVariableIndex);
        }

        /// <summary>
        /// Creates a PUSHLFX (push local indexed float) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction PUSHLFX(short localFloatVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHLFX, localFloatVariableIndex);
        }

        /// <summary>
        /// Creates a POPLIX (pop local indexed int) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction POPLIX(short localIntVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.POPLIX, localIntVariableIndex);
        }

        /// <summary>
        /// Creates a POPLFX (pop local indexed float) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction POPLFX(short localFloatVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.POPLFX, localFloatVariableIndex);
        }

        /// <summary>
        /// Creates a PUSHSTR (push string) instruction.
        /// </summary>
        /// <param name="value">The operand value.</param>
        /// <returns>A <see cref="FlowScriptInstruction"/> instance.</returns>
        public static FlowScriptInstruction PUSHSTR(short stringIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHSTR, stringIndex);
        }

        /// <summary>
        /// Represents an instruction operand value.
        /// </summary>
        public class OperandValue
        {
            private ValueType mType;
            private short mShortValue;
            private int mIntValue;
            private float mFloatValue;

            /// <summary>
            /// Gets the value type of the operand.
            /// </summary>
            public ValueType Type
            {
                get { return mType; }
            }

            /// <summary>
            /// Constructs a new operand value.
            /// </summary>
            /// <param name="value">The operand value.</param>
            public OperandValue(short value)
            {
                mType = ValueType.Int16;
                mShortValue = value;
            }

            /// <summary>
            /// Constructs a new operand value.
            /// </summary>
            /// <param name="value">The operand value.</param>
            public OperandValue(int value)
            {
                mType = ValueType.Int32;
                mIntValue = value;
            }

            /// <summary>
            /// Constructs a new operand value.
            /// </summary>
            /// <param name="value">The operand value.</param>
            public OperandValue(float value)
            {
                mType = ValueType.Single;
                mFloatValue = value;
            }

            /// <summary>
            /// Gets the operand value.
            /// </summary>
            /// <returns>The operand value.</returns>
            public object GetValue()
            {
                switch (mType)
                {
                    case ValueType.None:
                        throw new InvalidOperationException("This operand has no value");

                    case ValueType.Int16:
                        return mShortValue;

                    case ValueType.Int32:
                        return mIntValue;

                    case ValueType.Single:
                        return mFloatValue;

                    default:
                        throw new Exception("Invalid value type");
                }
            }

            /// <summary>
            /// Gets the <see cref="Int16"/> operand value.
            /// </summary>
            /// <returns>The <see cref="Int16"/> operand value.</returns>
            public Int16 GetInt16Value()
            {
                if (mType != ValueType.Int16)
                    throw new InvalidOperationException($"This operand does not have a value of type {ValueType.Int16}");

                return mShortValue;
            }

            /// <summary>
            /// Gets the <see cref="Int32"/> operand value.
            /// </summary>
            /// <returns>The <see cref="Int32"/> operand value.</returns>
            public Int32 GetInt32Value()
            {
                if (mType != ValueType.Int32)
                    throw new InvalidOperationException($"This operand does not have a value of type {ValueType.Int32}");

                return mIntValue;
            }

            /// <summary>
            /// Gets the <see cref="Single"/> operand value.
            /// </summary>
            /// <returns>The <see cref="Single"/> operand value.</returns>
            public Single GetSingleValue()
            {
                if (mType != ValueType.Single)
                    throw new InvalidOperationException($"This operand does not have a value of type {ValueType.Single}");

                return mFloatValue;
            }

            /// <summary>
            /// Represents the value types an operand can contain.
            /// </summary>
            public enum ValueType
            {
                None,
                Int16,
                Int32,
                Single,
            }
        }
    }
}
