using System.Collections.Generic;
using System;
using System.Linq;
using System.Diagnostics;

using AtlusScriptLib.Common.Syntax;
using AtlusScriptLib.Common.Collections;
using AtlusScriptLib.FunctionTables;
using AtlusScriptLib.BinaryModel;

namespace AtlusScriptLib.Parsers
{
    public sealed class FlowScriptBinarySyntaxParser
    {
        private FlowScriptBinary mScript;
        private int mInstructionIndex;
        private Stack<Expression> mValueStack;
        private FunctionCallOperator mLastCommCall;
        private IFunctionTable mCommTable;
        private Dictionary<FlowScriptOpcode, Func<Expression>> mOperatorMap;

        public FlowScriptBinarySyntaxParser()
        {
            mOperatorMap = new Dictionary<FlowScriptOpcode, Func<Expression>>()
            {
                { FlowScriptOpcode.ADD,   () => { return new BinaryAddOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.SUB,   () => { return new BinarySubtractOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.MUL,   () => { return new BinaryMultiplyOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.DIV,   () => { return new BinaryDivideOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.MINUS, () => { return new UnaryMinusOperator(mValueStack.Pop()); } },
                { FlowScriptOpcode.NOT,   () => { return new UnaryNotOperator(mValueStack.Pop()); } },
                { FlowScriptOpcode.OR,    () => { return new BinaryLogicalOrOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.AND,   () => { return new BinaryLogicalAndOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.EQ,    () => { return new BinaryEqualityOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.NEQ,   () => { return new BinaryNonEqualityOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.S,     () => { return new BinaryLessThanOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.L,     () => { return new BinaryGreaterThanOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.SE,    () => { return new BinaryLessThanOrEqualOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptOpcode.LE,    () => { return new BinaryGreaterThanOrEqualOperator(mValueStack.Pop(), mValueStack.Pop()); } },
            };
        }

        private string GetIntVariableName( int index )
        {
            return $"varInt{index}";
        }

        private string GetFloatVariableName( int index )
        {
            return $"varFloat{index}";
        }

        private int CalculateProcedureLength()
        {
            int endIndex = mInstructionIndex;
            while ( ++endIndex < mScript.TextSection.Count )
            {
                // Start of new procedure
                if ( mScript.TextSection[endIndex].Opcode == FlowScriptOpcode.PROC )
                {
                    break;
                }
            }

            // No new procedure found- this is the last procedure left
            if ( mScript.TextSection[endIndex - 1].Opcode != FlowScriptOpcode.END )
                Trace.TraceError( "Expected END opcode at end of procedure" );

            return ( endIndex - mInstructionIndex ) - 1;
        }

        private void ParseBinaryArithmic<T>( Func<Expression, Expression, T> ctor, ref List<Statement> statements )
            where T : BinaryExpression
        {
            var node = ctor( mValueStack.Pop(), mValueStack.Pop() );

            // Simulate return value by pushing the expression itslef onto the value stack
            mValueStack.Push( node );

            // remove old statements
            statements.RemoveLast( node.LeftOperand, node.RightOperand );

            // Add new binary expression statement
            statements.Add( node );
        }

        private CompoundStatement ParseProcedureBody( int length )
        {
            // for compound statement construction later
            var statements = new List<Statement>();

            while ( --length > 0 )
            {
                var instruction = mScript.TextSection[++mInstructionIndex];

                // jump labels can appear anywhere, so check if there is one present at the current location
                foreach ( var jumpLabel in mScript.JumpLabelSection.Where( x => x.InstructionIndex == mInstructionIndex ) )
                {
                    statements.Add( new LabeledStatement( new Identifier( jumpLabel.Name ), null ) );
                }

                switch ( instruction.Opcode )
                {
                    case FlowScriptOpcode.PUSHI:
                        mValueStack.Push( new IntConstant( mScript.TextSection[++mInstructionIndex].OperandInt ) );
                        break;

                    case FlowScriptOpcode.PUSHF:
                        mValueStack.Push( new FloatConstant( mScript.TextSection[++mInstructionIndex].OperandFloat ) );
                        break;

                    case FlowScriptOpcode.PUSHIX:
                        throw new Exception();

                    case FlowScriptOpcode.PUSHIF:
                        throw new Exception();

                    case FlowScriptOpcode.PUSHREG:
                        {
                            if ( mLastCommCall == null )
                                throw new Exception();

                            mValueStack.Push( mLastCommCall );
                            statements.RemoveLast( mLastCommCall );
                            statements.Add( mLastCommCall );
                        }
                        break;

                    case FlowScriptOpcode.POPIX:
                        throw new Exception();

                    case FlowScriptOpcode.POPFX:
                        throw new Exception();

                    case FlowScriptOpcode.PROC:
                        throw new Exception();

                    case FlowScriptOpcode.COMM:
                        {
                            if ( mCommTable == null )
                            {
                                mLastCommCall = new FunctionCallOperator(
                                    new Identifier( "__comm" ),
                                    new FunctionArgumentList( new IntConstant( instruction.OperandShort ) )
                                );
                            }
                            else
                            {
                                var commEntry = mCommTable[instruction.OperandShort];

                                var arguments = new List<Statement>();
                                foreach ( var arg in commEntry.Declaration.ArgumentList )
                                {
                                    // todo: type checking
                                    var value = mValueStack.Pop();

                                    statements.RemoveLast( value );
                                    arguments.Add( value );
                                }

                                mLastCommCall = new FunctionCallOperator(
                                    commEntry.Declaration.Identifier,
                                    new FunctionArgumentList( arguments )
                                );
                            }

                            statements.Add( mLastCommCall );
                        }
                        break;

                    case FlowScriptOpcode.END:
                        {
                            statements.Add( new ReturnStatement() );
                        }
                        break;

                    case FlowScriptOpcode.JUMP:
                        {
                            statements.Add( new GotoStatement(
                                new Identifier( mScript.ProcedureLabelSection[instruction.OperandShort].Name )
                            ) );
                        }
                        break;

                    case FlowScriptOpcode.CALL:
                        {
                            statements.Add( new FunctionCallOperator(
                                new Identifier( mScript.ProcedureLabelSection[instruction.OperandShort].Name )
                            ) );
                        }
                        break;

                    case FlowScriptOpcode.RUN:
                        throw new Exception();

                    case FlowScriptOpcode.GOTO:
                        {
                            statements.Add( new GotoStatement(
                                new Identifier( mScript.JumpLabelSection[instruction.OperandShort].Name )
                            ) );
                        }
                        break;

                    case FlowScriptOpcode.ADD:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryAddOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.SUB:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinarySubtractOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.MUL:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryMultiplyOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.DIV:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryDivideOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.MINUS:
                        {
                            var node = new UnaryMinusOperator( mValueStack.Pop() );
                            mValueStack.Push( node );
                            statements.ReplaceLast( node, node.Operand );
                        }
                        break;

                    case FlowScriptOpcode.NOT:
                        {
                            var node = new UnaryNotOperator( mValueStack.Pop() );
                            mValueStack.Push( node );
                            statements.ReplaceLast( node, node.Operand );
                        }
                        break;

                    case FlowScriptOpcode.OR:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryLogicalOrOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.AND:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryLogicalAndOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.EQ:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryEqualityOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.NEQ:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryNonEqualityOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.S:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryLessThanOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.L:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryGreaterThanOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.SE:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryLessThanOrEqualOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.LE:
                        ParseBinaryArithmic( ( Expression l, Expression r ) => { return new BinaryGreaterThanOrEqualOperator( l, r ); }, ref statements );
                        break;

                    case FlowScriptOpcode.IF:
                        {
                            var jumpLabel = mScript.JumpLabelSection[instruction.OperandShort];
                            var condition = mValueStack.Pop();

                            // remove expression that is evaluated in the if condition and place it in the if statement instead
                            statements.RemoveLast( condition );

                            // fix up later
                            statements.Add( new Selection(
                                condition,
                                null,
                                new CompoundStatement(
                                    new GotoStatement( new Identifier( jumpLabel.Name ) )
                            ) ) );

                        }
                        break;

                    case FlowScriptOpcode.PUSHIS:
                        mValueStack.Push( new ShortConstant( instruction.OperandShort ) );
                        break;

                    case FlowScriptOpcode.PUSHLIX:
                        mValueStack.Push( new Identifier( GetIntVariableName( instruction.OperandShort ) ) );
                        break;

                    case FlowScriptOpcode.PUSHLFX:
                        mValueStack.Push( new Identifier( GetFloatVariableName( instruction.OperandShort ) ) );
                        break;

                    case FlowScriptOpcode.POPLIX:
                        {
                            var node = new VariableDefinition(
                                new Identifier( GetIntVariableName( instruction.OperandShort ) ),
                                VariableDeclarationFlags.TypeInt,
                                mValueStack.Pop()
                            );

                            statements.RemoveLast( node.Initializer );
                            statements.Add( node );
                        }
                        break;

                    case FlowScriptOpcode.POPLFX:
                        {
                            var node = new VariableDefinition(
                                new Identifier( GetFloatVariableName( instruction.OperandShort ) ),
                                VariableDeclarationFlags.TypeFloat,
                                mValueStack.Pop()
                            );

                            statements.RemoveLast( node.Initializer );
                            statements.Add( node );
                        }
                        break;

                    case FlowScriptOpcode.PUSHSTR:
                        {
                            string value = string.Empty;
                            for ( int i = instruction.OperandShort; i < mScript.StringSection.Count; i++ )
                            {
                                if ( mScript.StringSection[i] == 0 )
                                    break;

                                value += ( char )mScript.StringSection[i];
                            }

                            mValueStack.Push( new StringConstant( value ) );
                        }
                        break;

                    default:
                        throw new Exception();
                }
            }

            return new CompoundStatement( statements );
        }

        public SyntaxTree Parse( FlowScriptBinary script, IFunctionTable commTable )
        {
            mScript = script;
            mInstructionIndex = 0;
            mValueStack = new Stack<Expression>();
            mCommTable = commTable;

            var tree = new SyntaxTree();

            for ( ; mInstructionIndex < script.TextSection.Count; mInstructionIndex++ )
            {
                var instruction = script.TextSection[mInstructionIndex];

                switch ( instruction.Opcode )
                {
                    case FlowScriptOpcode.PROC:
                        {
                            tree.Nodes.Add( new FunctionDefinition(
                                new Identifier( script.ProcedureLabelSection[instruction.OperandShort].Name ),
                                ParseProcedureBody( CalculateProcedureLength() ) )
                            );
                        }
                        break;

                    case FlowScriptOpcode.END:
                        break;

                    default:
                        throw new Exception();
                }
            }

            Debug.WriteLine( tree.Nodes[0].ToString() );

            return tree;
        }
    }
}
