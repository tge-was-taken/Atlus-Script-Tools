using System;

namespace AtlusScriptLib
{
    public class FlowScriptInstruction
    {
        private FlowScriptOpcode mOpcode;
        private OperandValue mOperand;

        public FlowScriptOpcode Opcode
        {
            get { return mOpcode; }
        }

        public OperandValue Operand
        {
            get { return mOperand; }
        }

        public bool UsesTwoBinaryInstructions
        {
            get { return mOpcode == FlowScriptOpcode.PUSHI || mOpcode == FlowScriptOpcode.PUSHF; }
        }

        private FlowScriptInstruction(FlowScriptOpcode opcode)
        {
            mOpcode = opcode;
            mOperand = null;
        }

        private FlowScriptInstruction(FlowScriptOpcode opcode, short value)
        {
            mOpcode = opcode;
            mOperand = new OperandValue(value);
        }

        private FlowScriptInstruction(FlowScriptOpcode opcode, int value)
        {
            mOpcode = opcode;
            mOperand = new OperandValue(value);
        }

        private FlowScriptInstruction(FlowScriptOpcode opcode, float value)
        {
            mOpcode = opcode;
            mOperand = new OperandValue(value);
        }

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

        public static FlowScriptInstruction PUSHI(int value)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHI, value);
        }

        public static FlowScriptInstruction PUSHF(float value)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHF, value);
        }

        public static FlowScriptInstruction PUSHIX(short globalIntVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHIX, globalIntVariableIndex);
        }

        public static FlowScriptInstruction PUSHIF(short globalFloatVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHIF, globalFloatVariableIndex);
        }

        public static FlowScriptInstruction PUSHREG()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHREG);
        }

        public static FlowScriptInstruction POPIX(short globalIntVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.POPIX, globalIntVariableIndex);
        }

        public static FlowScriptInstruction POPFX(short globalFloatVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.POPFX, globalFloatVariableIndex);
        }

        public static FlowScriptInstruction PROC(short procedureIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PROC, procedureIndex);
        }

        public static FlowScriptInstruction COMM(short functionId)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.COMM, functionId);
        }

        public static FlowScriptInstruction END()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.END);
        }

        public static FlowScriptInstruction JUMP(short procedureLabelIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.JUMP, procedureLabelIndex);
        }

        public static FlowScriptInstruction CALL(short procedureLabelIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.CALL, procedureLabelIndex);
        }

        public static FlowScriptInstruction RUN()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.RUN);
        }

        public static FlowScriptInstruction GOTO(short jumpLabelIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.GOTO, jumpLabelIndex);
        }

        public static FlowScriptInstruction ADD()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.ADD);
        }

        public static FlowScriptInstruction SUB()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.SUB);
        }

        public static FlowScriptInstruction MUL()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.MUL);
        }

        public static FlowScriptInstruction DIV()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.DIV);
        }

        public static FlowScriptInstruction MINUS()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.MINUS);
        }

        public static FlowScriptInstruction NOT()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.NOT);
        }

        public static FlowScriptInstruction OR()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.OR);
        }

        public static FlowScriptInstruction AND()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.AND);
        }

        public static FlowScriptInstruction EQ()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.EQ);
        }

        public static FlowScriptInstruction NEQ()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.NEQ);
        }

        public static FlowScriptInstruction S()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.S);
        }

        public static FlowScriptInstruction L()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.L);
        }

        public static FlowScriptInstruction SE()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.SE);
        }

        public static FlowScriptInstruction LE()
        {
            return new FlowScriptInstruction(FlowScriptOpcode.LE);
        }

        public static FlowScriptInstruction IF(short jumpLabelIndexIfFalse)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.IF, jumpLabelIndexIfFalse);
        }

        public static FlowScriptInstruction PUSHIS(short value)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHIS, value);
        }

        public static FlowScriptInstruction PUSHLIX(short localIntVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHLIX, localIntVariableIndex);
        }

        public static FlowScriptInstruction PUSHLFX(short localFloatVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHLFX, localFloatVariableIndex);
        }

        public static FlowScriptInstruction POPLIX(short localIntVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.POPLIX, localIntVariableIndex);
        }

        public static FlowScriptInstruction POPLFX(short localFloatVariableIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.POPLFX, localFloatVariableIndex);
        }

        public static FlowScriptInstruction PUSHSTR(short stringIndex)
        {
            return new FlowScriptInstruction(FlowScriptOpcode.PUSHSTR, stringIndex);
        }

        public class OperandValue
        {
            private ValueType mType;
            private short mShortValue;
            private int mIntValue;
            private float mFloatValue;

            public ValueType Type
            {
                get { return mType; }
            }

            public OperandValue(short value)
            {
                mType = ValueType.Int16;
                mShortValue = value;
            }

            public OperandValue(int value)
            {
                mType = ValueType.Int32;
                mIntValue = value;
            }

            public OperandValue(float value)
            {
                mType = ValueType.Single;
                mFloatValue = value;
            }

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

            public Int16 GetInt16Value()
            {
                if (mType != ValueType.Int16)
                    throw new InvalidOperationException($"This operand does not have a value of type {ValueType.Int16}");

                return mShortValue;
            }
            public Int32 GetInt32Value()
            {
                if (mType != ValueType.Int32)
                    throw new InvalidOperationException($"This operand does not have a value of type {ValueType.Int32}");

                return mIntValue;
            }

            public Single GetSingleValue()
            {
                if (mType != ValueType.Single)
                    throw new InvalidOperationException($"This operand does not have a value of type {ValueType.Single}");

                return mFloatValue;
            }

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
