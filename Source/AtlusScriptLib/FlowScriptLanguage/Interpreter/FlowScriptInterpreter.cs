using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace AtlusScriptLib.FlowScriptLanguage.Interpreter
{
    public class FlowScriptInterpreter
    {
        private static readonly Action< FlowScriptInterpreter >[] sOpcodeHandlers =
        {
            PUSHI, PUSHF, PUSHIX, PUSHIF, PUSHREG,
            POPIX, POPFX, PROC, COMM, END, JUMP,
            CALL, RUN, GOTO, ADD, SUB,
            MUL, DIV, MINUS, NOT, OR,
            AND, EQ, NEQ, S, L,
            SE, LE, IF, PUSHIS, PUSHLIX,
            PUSHLFX, POPLIX, POPLFX, PUSHSTR
        };

        // Static
        private static readonly int[] sGlobalIntVariablePool = new int[255];
        private static readonly float[] sGlobalFloatVariablePool = new float[255];

        // Instance
        private readonly FlowScript mScript;
        private int mProcedureIndex;
        private int mInstructionIndex;
        private readonly Stack<StackValue> mStack;
        private StackValue mCommReturnValue;
        private readonly int[] mLocalIntVariablePool;
        private readonly float[] mLocalFloatVariablePool;

        private int ProcedureIndex
        {
            get => mProcedureIndex;
            set => mProcedureIndex = value;
        }

        private Procedure Procedure => mScript.Procedures[ mProcedureIndex ];

        private int InstructionIndex
        {
            get => mInstructionIndex;
            set => mInstructionIndex = value;
        }

        private Instruction Instruction => Procedure.Instructions[ mInstructionIndex ];

        public FlowScriptInterpreter( FlowScript flowScript )
        {
            mScript = flowScript;
            mProcedureIndex = 0;
            mInstructionIndex = 0;
            mStack = new Stack< StackValue >();
            mCommReturnValue = new StackValue( StackValueKind.Int, 0 );
            mLocalIntVariablePool = new int[100];
            mLocalFloatVariablePool = new float[100];
        }

        public void Run()
        {
            while ( mInstructionIndex < Procedure.Instructions.Count )
                Step();

            if ( mStack.Count > 1 )
                throw new StackInbalanceException();
        }

        public void Step()
        {
            // Save current instruction index for later
            var prevProcedureIndex = ProcedureIndex;
            var prevInstructionIndex = InstructionIndex;

            // Invoke handler
            sOpcodeHandlers[ ( int ) Instruction.Opcode ]( this );

            // Only increment instruction index if opcode didn't modify it
            if ( ProcedureIndex == prevProcedureIndex && InstructionIndex == prevInstructionIndex )
                ++InstructionIndex;
        }

        private bool IsStackEmpty() => mStack.Count == 0;

        // Push
        private void PushValue( StackValue stackValue )
        {
            mStack.Push( stackValue );
        }

        private void PushValue( StackValueKind kind, object value )
        {
            PushValue( new StackValue( kind, value ) );
        }

        private void PushValue( int value )
        {
            PushValue( StackValueKind.Int, value );
        }

        private void PushValue( bool value )
        {
            PushValue( StackValueKind.Int, value ? 1 : 0 );
        }

        private void PushValue( float value )
        {
            PushValue( StackValueKind.Float, value );
        }

        private void PushValue( string value )
        {
            PushValue( StackValueKind.String, value );
        }

        // Pop
        private StackValue PopValue()
        {
            if ( IsStackEmpty() )
                throw new StackUnderflowException();

            return mStack.Pop();
        }

        private StackValue PopArithmicValue()
        {
            var value = PopValue();

            if ( value.Kind == StackValueKind.String || value.Kind == StackValueKind.ReturnIndex )
            {
                throw new InvalidStackValueTypeException( $"Attempted to perform arithmic on a {value.Kind} value" );
            }

            return value;
        }

        private int PopIntValue()
        {
            var value = PopValue();

            switch ( value.Kind )
            {
                case StackValueKind.Int:
                    return ( int )value.Value;

                case StackValueKind.Float:
                    return ( int )( float )value.Value;

                case StackValueKind.GlobalIntVariable:
                    return sGlobalIntVariablePool[( int )value.Value];

                case StackValueKind.GlobalFloatVariable:
                    return ( int )sGlobalFloatVariablePool[ ( int ) value.Value ];

                default:
                    throw new InvalidStackValueTypeException( StackValueKind.Int, value.Kind );
            }
        }

        private float PopFloatValue()
        {
            var value = PopValue();

            switch ( value.Kind )
            {
                case StackValueKind.Int:
                    return ( float )( int )value.Value;

                case StackValueKind.Float:
                    return ( float )value.Value;

                case StackValueKind.GlobalIntVariable:
                    return ( float )sGlobalIntVariablePool[( int )value.Value];

                case StackValueKind.GlobalFloatVariable:
                    return sGlobalFloatVariablePool[( int )value.Value];

                default:
                    throw new InvalidStackValueTypeException( StackValueKind.Float, value.Kind );
            }
        }

        private string PopStringValue()
        {
            var value = PopValue();
            if ( value.Kind != StackValueKind.String )
            {
                throw new InvalidStackValueTypeException( StackValueKind.String, value.Kind );
            }

            return (string)value.Value;
        }

        private bool PopBooleanValue()
        {
            return PopIntValue() == 1;
        }

        // COMM pop/push stuff
        private void SetReturnValue( StackValue stackValue )
        {
            mCommReturnValue = stackValue;
        }

        private void SetReturnValue( StackValueKind kind, object value )
        {
            SetReturnValue( new StackValue( kind, value ) );
        }

        private void SetIntReturnValue( int value )
        {
            SetReturnValue( StackValueKind.Int, value );
        }

        private void SetBoolReturnValue( bool value )
        {
            SetIntReturnValue( value ? 1 : 0 );
        }

        private void SetFloatReturnValue( float value )
        {
            SetReturnValue( StackValueKind.Float, value );
        }

        // Opcode handlers
        private static void PUSHI( FlowScriptInterpreter instance )
        {
            instance.PushValue( instance.Instruction.Operand.Int32Value );
        }

        private static void PUSHF( FlowScriptInterpreter instance )
        {
            instance.PushValue( instance.Instruction.Operand.SingleValue );
        }

        private static void PUSHIX( FlowScriptInterpreter instance )
        {
            instance.PushValue( sGlobalIntVariablePool[instance.Instruction.Operand.Int16Value] );
        }

        private static void PUSHIF( FlowScriptInterpreter instance )
        {
            instance.PushValue( sGlobalFloatVariablePool[instance.Instruction.Operand.Int16Value] );
        }

        private static void PUSHREG( FlowScriptInterpreter instance )
        {
            instance.PushValue( instance.mCommReturnValue );
        }

        private static void POPIX( FlowScriptInterpreter instance )
        {
            sGlobalIntVariablePool[ instance.Instruction.Operand.Int16Value ] = instance.PopIntValue();
        }

        private static void POPFX( FlowScriptInterpreter instance )
        {
            sGlobalFloatVariablePool[instance.Instruction.Operand.Int16Value] = instance.PopFloatValue();
        }

        private static void PROC( FlowScriptInterpreter instance )
        {
           // Nothing to do?
        }

        private static void COMM( FlowScriptInterpreter instance )
        {
            var index = instance.Instruction.Operand.Int16Value;

            // TODO
            if ( index == 0x0003 )
            {
                // PUTS
                var format = instance.PopStringValue();

                for ( int i = 0; i < format.Length; i++ )
                {
                    var c = format[ i ];

                    if ( c == '%' && ++i < format.Length )
                    {
                        var next = format[ i ];

                        switch ( next )
                        {
                            case 'c':
                            case 's':
                                Console.Write( instance.PopStringValue() );
                                break;

                            case 'd':
                            case 'i':
                            case 'o':
                            case 'x':
                            case 'X':
                            case 'u':
                                Console.Write( instance.PopIntValue() );
                                break;

                            case 'f':
                            case 'F':
                            case 'e':
                            case 'E':
                            case 'a':
                            case 'A':
                            case 'g':
                            case 'G':
                                Console.Write( instance.PopFloatValue() );
                                break;
                        }
                    }
                    else
                    {
                        Console.Write( c );
                    }
                }

                Console.Write( '\n' );
            }
            else if ( index == 0x00B6 )
            {
                instance.SetFloatReturnValue( ( float ) Math.Sin( instance.PopFloatValue() ) );
            }
            else if ( index == 0x00B7 )
            {
                instance.SetFloatReturnValue( ( float ) Math.Cos( instance.PopFloatValue() ) );
            }
            else
            {
                throw new NotImplementedException( $"COMM function: {index:X8}" );
            }
        }

        private static void END( FlowScriptInterpreter instance )
        {
            // Nothing to return to if stack is empty
            if ( instance.IsStackEmpty() )
                return;

            // Set procedure & instruction index to the one we stored during CALL
            var returnIndexValue = instance.PopValue();
            if ( returnIndexValue.Kind != StackValueKind.ReturnIndex )
                throw new InvalidStackValueTypeException( StackValueKind.ReturnIndex, returnIndexValue.Kind );

            var returnIndex = ( long ) returnIndexValue.Value;
            instance.ProcedureIndex = ( int ) ( returnIndex >> 32 );
            instance.InstructionIndex = ( int )returnIndex + 1;
        }

        private static void JUMP( FlowScriptInterpreter instance )
        {
            var index = instance.Instruction.Operand.Int16Value;
            instance.InstructionIndex = instance.Procedure.Labels[index].InstructionIndex;
        }

        private static void CALL( FlowScriptInterpreter instance )
        {
            instance.PushValue( StackValueKind.ReturnIndex, ( ( long )instance.ProcedureIndex << 32 ) | ( long )instance.InstructionIndex );
            instance.ProcedureIndex = instance.Instruction.Operand.Int16Value;
            instance.InstructionIndex = 0;
        }

        private static void RUN( FlowScriptInterpreter instance )
        {
            throw new NotImplementedException();
        }

        private static void GOTO( FlowScriptInterpreter instance )
        {
            var index = instance.Instruction.Operand.Int16Value;
            instance.InstructionIndex = instance.Procedure.Labels[index].InstructionIndex;
        }

        private static void ADD( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            var r = instance.PopArithmicValue();
            instance.PushValue( ( dynamic )l.Value + ( dynamic )r.Value );
        }

        private static void SUB( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            var r = instance.PopArithmicValue();
            instance.PushValue( ( dynamic )l.Value - ( dynamic )r.Value );
        }

        private static void MUL( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            var r = instance.PopArithmicValue();
            instance.PushValue( ( dynamic )l.Value * ( dynamic )r.Value );
        }

        private static void DIV( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            var r = instance.PopArithmicValue();
            instance.PushValue( ( dynamic )l.Value / ( dynamic )r.Value );
        }

        private static void MINUS( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            instance.PushValue( -( dynamic )l.Value );
        }

        private static void NOT( FlowScriptInterpreter instance )
        {
            var o = instance.PopBooleanValue();
            instance.PushValue( !o );
        }

        private static void OR( FlowScriptInterpreter instance )
        {
            var l = instance.PopBooleanValue();
            var r = instance.PopBooleanValue();
            instance.PushValue( l || r );
        }

        private static void AND( FlowScriptInterpreter instance )
        {
            var l = instance.PopBooleanValue();
            var r = instance.PopBooleanValue();
            instance.PushValue( l && r );
        }

        private static void EQ( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            var r = instance.PopArithmicValue();
            instance.PushValue( ( dynamic ) l.Value == ( dynamic ) r.Value );
        }

        private static void NEQ( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            var r = instance.PopArithmicValue();
            instance.PushValue( ( dynamic )l.Value != ( dynamic )r.Value );
        }

        private static void S( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            var r = instance.PopArithmicValue();
            instance.PushValue( ( dynamic )l.Value < ( dynamic )r.Value );
        }

        private static void L( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            var r = instance.PopArithmicValue();
            instance.PushValue( ( dynamic )l.Value > ( dynamic )r.Value );
        }

        private static void SE( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            var r = instance.PopArithmicValue();
            instance.PushValue( ( dynamic )l.Value <= ( dynamic )r.Value );
        }

        private static void LE( FlowScriptInterpreter instance )
        {
            var l = instance.PopArithmicValue();
            var r = instance.PopArithmicValue();
            instance.PushValue( ( dynamic )l.Value >= ( dynamic )r.Value );
        }

        private static void IF( FlowScriptInterpreter instance )
        {
            var condition = instance.PopBooleanValue();
            if ( condition )
                return;

            // Jump to false label
            var index = instance.Instruction.Operand.Int16Value;
            var label = instance.Procedure.Labels[ index ];
            instance.InstructionIndex = label.InstructionIndex;
        }

        private static void PUSHIS( FlowScriptInterpreter instance )
        {
            var value = instance.Instruction.Operand.Int16Value;
            instance.PushValue( value );
        }

        private static void PUSHLIX( FlowScriptInterpreter instance )
        {
            var index = instance.Instruction.Operand.Int16Value;
            var value = instance.mLocalIntVariablePool[ index ];
            instance.PushValue( value );
        }

        private static void PUSHLFX( FlowScriptInterpreter instance )
        {
            var index = instance.Instruction.Operand.Int16Value;
            var value = instance.mLocalFloatVariablePool[index];
            instance.PushValue( value );
        }

        private static void POPLIX( FlowScriptInterpreter instance )
        {
            var index = instance.Instruction.Operand.Int16Value;
            instance.mLocalIntVariablePool[index] = instance.PopIntValue();
        }

        private static void POPLFX( FlowScriptInterpreter instance )
        {
            var index = instance.Instruction.Operand.Int16Value;
            instance.mLocalFloatVariablePool[ index ] = instance.PopFloatValue();
        }

        private static void PUSHSTR( FlowScriptInterpreter instance )
        {
            instance.PushValue( instance.Instruction.Operand.StringValue );
        }
    }
}
