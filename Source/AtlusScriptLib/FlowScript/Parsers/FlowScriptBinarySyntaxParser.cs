using System.Collections.Generic;
using System;
using System.Linq;
using MoreLinq;

using AtlusScriptLib.Shared.Syntax;
using System.Diagnostics;
using AtlusScriptLib.Shared.Utilities;

namespace AtlusScriptLib.FlowScript.Parsers
{
    public class FlowScriptBinarySyntaxParser
    {
        private FlowScriptBinary mScript;
        private int mInstructionIndex;
        private Stack<Expression> mValueStack;
        private FunctionCallOperator mLastCommCall;

        public FlowScriptBinarySyntaxParser()
        {
        }

        private string GetIntVariableName(int index)
        {
            return $"varInt{index}";
        }

        private string GetFloatVariableName(int index)
        {
            return $"varFloat{index}";
        }

        private int CalculateProcedureLength()
        {
            int endIndex = mInstructionIndex;
            while (++endIndex < mScript.TextSectionData.Count)
            {
                // Start of new procedure
                if (mScript.TextSectionData[endIndex].Opcode == FlowScriptBinaryOpcode.PROC)
                {
                    break;
                }
            }

            // No new procedure found- this is the last procedure left
            if (mScript.TextSectionData[endIndex - 1].Opcode != FlowScriptBinaryOpcode.END)
                DebugUtils.TraceError("Expected END opcode at end of procedure");

            return (endIndex - mInstructionIndex) - 1;
        }

        private CompoundStatement ParseProcedureBody(int length)
        {
            // for compound statement construction later
            var statements = new List<Statement>();

            while (--length > 0)
            {
                var instruction = mScript.TextSectionData[++mInstructionIndex];

                // jump labels can appear anywhere, so check if there is one present at the current location
                var jumpLabels = mScript.JumpLabelSectionData.Where(x => x.Offset == mInstructionIndex);
                foreach (var item in jumpLabels)
                {
                    statements.Add(new LabeledStatement(new Identifier(item.Name), null));
                }

                void parseBinaryArithmic<T>(Func<Expression, Expression, T> ctor)
                    where T : BinaryArithmicExpression
                {
                    var node = ctor(mValueStack.Pop(), mValueStack.Pop());
                    statements.Remove(node.LeftOperand);
                    statements.Remove(node.RightOperand);
                    statements.Add(node);
                    mValueStack.Push(node);
                }

                switch (instruction.Opcode)
                {
                    case FlowScriptBinaryOpcode.PUSHI:
                        mValueStack.Push(new IntLiteral(mScript.TextSectionData[++mInstructionIndex].OperandInt));
                        break;

                    case FlowScriptBinaryOpcode.PUSHF:
                        mValueStack.Push(new FloatLiteral(mScript.TextSectionData[++mInstructionIndex].OperandFloat));
                        break;

                    case FlowScriptBinaryOpcode.PUSHIX:
                        throw new Exception();

                    case FlowScriptBinaryOpcode.PUSHIF:
                        throw new Exception();

                    case FlowScriptBinaryOpcode.PUSHREG:
                        {
                            if (mLastCommCall == null)
                                throw new Exception();
                            
                            mValueStack.Push(mLastCommCall);

                            int last = statements.FindLastIndex(x => x == mLastCommCall);
                            if (last == -1)
                                throw new Exception();

                            statements.RemoveAt(last);
                        }
                        break;

                    case FlowScriptBinaryOpcode.POPIX:
                        throw new Exception();

                    case FlowScriptBinaryOpcode.POPFX:
                        throw new Exception();

                    case FlowScriptBinaryOpcode.PROC:
                        throw new Exception();

                    case FlowScriptBinaryOpcode.COMM:
                        {
                            // TODO: implement using COMM function table
                            mLastCommCall = new FunctionCallOperator(
                                new Identifier("__comm"),
                                new FunctionArgumentList(new IntLiteral(instruction.OperandShort))
                            );

                            statements.Add(mLastCommCall);
                        }
                        break;

                    case FlowScriptBinaryOpcode.END:
                        {
                            statements.Add(new ReturnStatement());
                        }
                        break;

                    case FlowScriptBinaryOpcode.JUMP:
                        {
                            statements.Add(new GotoStatement(
                                new Identifier(mScript.ProcedureLabelSectionData[instruction.OperandShort].Name)
                            ));
                        }
                        break;

                    case FlowScriptBinaryOpcode.CALL:
                        {
                            statements.Add(new FunctionCallOperator(
                                new Identifier(mScript.ProcedureLabelSectionData[instruction.OperandShort].Name)
                            ));
                        }
                        break;

                    case FlowScriptBinaryOpcode.RUN:
                        throw new Exception();

                    case FlowScriptBinaryOpcode.GOTO:
                        {
                            statements.Add(new GotoStatement(
                                new Identifier(mScript.JumpLabelSectionData[instruction.OperandShort].Name)
                            ));
                        }
                        break;

                    case FlowScriptBinaryOpcode.ADD:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryAddOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.SUB:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinarySubtractOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.MUL:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryMultiplyOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.DIV:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryDivideOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.MINUS:
                        {
                            var node = new UnaryMinusOperator(mValueStack.Pop());
                            statements.Remove(node.Operand);
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.NOT:
                        {
                            var node = new UnaryNotOperator(mValueStack.Pop());
                            statements.Remove(node.Operand);
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.OR:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryLogicalOrOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.AND:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryLogicalAndOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.EQ:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryEqualityOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.NEQ:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryNonEqualityOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.S:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryLessThanOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.L:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryGreaterThanOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.SE:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryLessThanOrEqualOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.LE:
                        parseBinaryArithmic((Expression l, Expression r) => { return new BinaryGreaterThanOrEqualOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.IF:
                        {
                            var trueBodyJumpLabel = mScript.JumpLabelSectionData[instruction.OperandShort];
                            var condition = mValueStack.Pop();

                            // remove expression that is evaluated in the if condition
                            int index = statements.FindLastIndex( x => x == condition);
                            if (index == -1)
                                throw new Exception();

                            statements.RemoveAt(index);

                            // and place it in the if statement instead
                            //statements.Add(new Selection(condition, bodyIfTrue, bodyIfFalse));
                            statements.Add(new Selection(
                                condition, 
                                new CompoundStatement(
                                    new GotoStatement(new Identifier(trueBodyJumpLabel.Name))
                                ), 
                                null)
                            );
                           
                        }
                        break;

                    case FlowScriptBinaryOpcode.PUSHIS:
                        mValueStack.Push(new ShortLiteral(instruction.OperandShort));
                        break;

                    case FlowScriptBinaryOpcode.PUSHLIX:
                        mValueStack.Push(new Identifier(GetIntVariableName(instruction.OperandShort)));
                        break;

                    case FlowScriptBinaryOpcode.PUSHLFX:
                        mValueStack.Push(new Identifier(GetFloatVariableName(instruction.OperandShort)));
                        break;

                    case FlowScriptBinaryOpcode.POPLIX:
                        {
                            var node = new VariableDefinition(
                                new Identifier(GetIntVariableName(instruction.OperandShort)),
                                VariableDeclarationFlags.TypeInt,
                                mValueStack.Pop()
                            );

                            statements.Add(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.POPLFX:
                        {
                            var node = new VariableDefinition(
                                new Identifier(GetFloatVariableName(instruction.OperandShort)),
                                VariableDeclarationFlags.TypeFloat,
                                mValueStack.Pop()
                            );

                            statements.Add(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.PUSHSTR:
                        mValueStack.Push(new StringLiteral(mScript.StringSectionData[instruction.OperandShort]));
                        break;

                    default:
                        throw new Exception();
                }
            }

            return new CompoundStatement(statements);
        }

        public SyntaxTree Parse(FlowScriptBinary script)
        {
            mScript = script;
            mInstructionIndex = 0;
            mValueStack = new Stack<Expression>();

            var tree = new SyntaxTree();

            for (; mInstructionIndex < script.TextSectionData.Count; mInstructionIndex++)
            {
                var instruction = script.TextSectionData[mInstructionIndex];

                switch (instruction.Opcode)
                {
                    case FlowScriptBinaryOpcode.PROC:
                        {
                            tree.Nodes.Add(new FunctionDefinition(
                                new Identifier(script.ProcedureLabelSectionData[instruction.OperandShort].Name),
                                ParseProcedureBody(CalculateProcedureLength()))
                            );
                        }
                        break;

                    case FlowScriptBinaryOpcode.END:
                        break;

                    default:
                        throw new Exception();
                }
            }

            Debug.WriteLine(tree.Nodes[0].ToString());

            return tree;
        }
    }
}
