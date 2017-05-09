using System.Collections.Generic;
using System;
using System.Linq;
using System.Diagnostics;

using MoreLinq;

using AtlusScriptLib.Shared.Syntax;
using AtlusScriptLib.Shared.Utilities;
using AtlusScriptLib.Shared.Collections;
using AtlusScriptLib.FlowScript.CommTables;

namespace AtlusScriptLib.FlowScript.Parser
{
    public class FlowScriptBinarySyntaxParser
    {
        private FlowScriptBinary mScript;
        private int mInstructionIndex;
        private Stack<Expression> mValueStack;
        private FunctionCallOperator mLastCommCall;
        private ICommTable mCommTable;
        private Dictionary<FlowScriptBinaryOpcode, Func<Expression>> mOperatorMap;

        public FlowScriptBinarySyntaxParser()
        {
            mOperatorMap = new Dictionary<FlowScriptBinaryOpcode, Func<Expression>>()
            {
                { FlowScriptBinaryOpcode.ADD,   () => { return new BinaryAddOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.SUB,   () => { return new BinarySubtractOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.MUL,   () => { return new BinaryMultiplyOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.DIV,   () => { return new BinaryDivideOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.MINUS, () => { return new UnaryMinusOperator(mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.NOT,   () => { return new UnaryNotOperator(mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.OR,    () => { return new BinaryLogicalOrOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.AND,   () => { return new BinaryLogicalAndOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.EQ,    () => { return new BinaryEqualityOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.NEQ,   () => { return new BinaryNonEqualityOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.S,     () => { return new BinaryLessThanOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.L,     () => { return new BinaryGreaterThanOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.SE,    () => { return new BinaryLessThanOrEqualOperator(mValueStack.Pop(), mValueStack.Pop()); } },
                { FlowScriptBinaryOpcode.LE,    () => { return new BinaryGreaterThanOrEqualOperator(mValueStack.Pop(), mValueStack.Pop()); } },
            };
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

        private void ParseBinaryArithmic<T>(Func<Expression, Expression, T> ctor, ref List<Statement> statements)
            where T : BinaryExpression
        {
            var node = ctor(mValueStack.Pop(), mValueStack.Pop());

            // Simulate return value by pushing the expression itslef onto the value stack
            mValueStack.Push(node);

            // remove old statements
            statements.RemoveLast(node.LeftOperand, node.RightOperand);

            // Add new binary expression statement
            statements.Add(node);
        }

        private CompoundStatement ParseProcedureBody(int length)
        {
            // for compound statement construction later
            var statements = new List<Statement>();

            while (--length > 0)
            {
                var instruction = mScript.TextSectionData[++mInstructionIndex];

                // jump labels can appear anywhere, so check if there is one present at the current location
                foreach (var jumpLabel in mScript.JumpLabelSectionData.Where(x => x.Offset == mInstructionIndex))
                {
                    statements.Add(new LabeledStatement(new Identifier(jumpLabel.Name), null));
                }

                switch (instruction.Opcode)
                {
                    case FlowScriptBinaryOpcode.PUSHI:
                        mValueStack.Push(new IntConstant(mScript.TextSectionData[++mInstructionIndex].OperandInt));
                        break;

                    case FlowScriptBinaryOpcode.PUSHF:
                        mValueStack.Push(new FloatConstant(mScript.TextSectionData[++mInstructionIndex].OperandFloat));
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
                            statements.RemoveLast(mLastCommCall);
                            statements.Add(mLastCommCall);
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
                            if (mCommTable == null)
                            {
                                mLastCommCall = new FunctionCallOperator(
                                    new Identifier("__comm"),
                                    new FunctionArgumentList(new IntConstant(instruction.OperandShort))
                                );
                            }
                            else
                            {
                                var commEntry = mCommTable[instruction.OperandShort];

                                var arguments = new List<Statement>();
                                foreach (var arg in commEntry.Declaration.ArgumentList)
                                {
                                    // todo: type checking
                                    var value = mValueStack.Pop();

                                    statements.RemoveLast(value);
                                    arguments.Add(value);
                                }

                                mLastCommCall = new FunctionCallOperator(
                                    commEntry.Declaration.Identifier,
                                    new FunctionArgumentList(arguments)
                                );
                            }

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
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryAddOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.SUB:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinarySubtractOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.MUL:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryMultiplyOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.DIV:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryDivideOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.MINUS:
                        {
                            var node = new UnaryMinusOperator(mValueStack.Pop());
                            mValueStack.Push(node);
                            statements.ReplaceLast(node, node.Operand);                       
                        }
                        break;

                    case FlowScriptBinaryOpcode.NOT:
                        {
                            var node = new UnaryNotOperator(mValueStack.Pop());
                            mValueStack.Push(node);
                            statements.ReplaceLast(node, node.Operand);                     
                        }
                        break;

                    case FlowScriptBinaryOpcode.OR:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryLogicalOrOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.AND:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryLogicalAndOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.EQ:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryEqualityOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.NEQ:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryNonEqualityOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.S:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryLessThanOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.L:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryGreaterThanOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.SE:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryLessThanOrEqualOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.LE:
                        ParseBinaryArithmic((Expression l, Expression r) => { return new BinaryGreaterThanOrEqualOperator(l, r); }, ref statements);
                        break;

                    case FlowScriptBinaryOpcode.IF:
                        {
                            var jumpLabel = mScript.JumpLabelSectionData[instruction.OperandShort];
                            var condition = mValueStack.Pop();

                            // remove expression that is evaluated in the if condition and place it in the if statement instead
                            statements.RemoveLast(condition);

                            // fix up later
                            statements.Add(new Selection(
                                condition,
                                null,
                                new CompoundStatement(
                                    new GotoStatement(new Identifier(jumpLabel.Name))
                            )));
                           
                        }
                        break;

                    case FlowScriptBinaryOpcode.PUSHIS:
                        mValueStack.Push(new ShortConstant(instruction.OperandShort));
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

                            statements.RemoveLast(node.Initializer);
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

                            statements.RemoveLast(node.Initializer);
                            statements.Add(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.PUSHSTR:
                        mValueStack.Push(new StringConstant(mScript.StringSectionData[instruction.OperandShort]));
                        break;

                    default:
                        throw new Exception();
                }
            }

            return new CompoundStatement(statements);
        }

        public SyntaxTree Parse(FlowScriptBinary script, ICommTable commTable)
        {
            mScript = script;
            mInstructionIndex = 0;
            mValueStack = new Stack<Expression>();
            mCommTable = commTable;

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
