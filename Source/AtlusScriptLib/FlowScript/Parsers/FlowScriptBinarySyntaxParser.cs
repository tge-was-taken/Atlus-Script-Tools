using System.Collections.Generic;
using System;
using System.Linq;
using MoreLinq;

using AtlusScriptLib.Shared.Syntax;

namespace AtlusScriptLib.FlowScript.Parsers
{
    enum CompoundStatementContext
    {
        Global,
        Procedure,
        If
    }

    public class FlowScriptBinarySyntaxParser
    {
        private FlowScriptBinary mScript;
        private int mInstructionIndex;
        private Stack<ExpressionStatement> mValueStack;
        private Stack<CompoundStatementContext> mContext;
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

        private CompoundStatement ParseCompoundStatement()
        {
            // for compound statement construction later
            var statements = new List<Statement>();

            // we're going to loop until we find an end instruction
            bool endFound = false;

            while (!endFound)
            {
                if (mInstructionIndex == mScript.TextSectionData.Count - 1)
                {
                    endFound = true;
                    continue;
                }

                var instruction = mScript.TextSectionData[++mInstructionIndex];

                var jumpLabels = mScript.JumpLabelSectionData.Where(x => x.Offset == mInstructionIndex);
                foreach (var item in jumpLabels)
                {
                    statements.Add(new LabeledStatement(new Identifier(item.Name), null));
                }

                void parseBinaryArithmic<T>(Func<ExpressionStatement, ExpressionStatement, T> ctor)
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
                            //mValueStack.Push(new Identifier("__commResult")); // TODO: implement using COMM function table

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
                            var context = mContext.Peek();
                            endFound = true;

                            switch (context)
                            {
                                case CompoundStatementContext.Procedure:
                                    statements.Add(new ReturnStatement());
                                    break;

                                case CompoundStatementContext.If:
                                    statements.Add(new BreakStatement());
                                    break;
                            }
                        }
                        break;

                    case FlowScriptBinaryOpcode.JUMP:
                        {
                            statements.Add(new GotoStatement(
                                new Identifier(mScript.JumpLabelSectionData[instruction.OperandShort].Name)
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
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryAddOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.SUB:
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinarySubtractOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.MUL:
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryMultiplyOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.DIV:
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryDivideOperator(l, r); });
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
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryLogicalOrOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.AND:
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryLogicalAndOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.EQ:
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryEqualityOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.NEQ:
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryNonEqualityOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.S:
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryLessThanOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.L:
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryGreaterThanOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.SE:
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryLessThanOrEqualOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.LE:
                        parseBinaryArithmic((ExpressionStatement l, ExpressionStatement r) => { return new BinaryGreaterThanOrEqualOperator(l, r); });
                        break;

                    case FlowScriptBinaryOpcode.IF:
                        {
                            var falseBodyJumpLabel = mScript.JumpLabelSectionData[instruction.OperandShort];
                            int bodyStartIndex = mInstructionIndex + 1;
                            int bodyLength = (int)(falseBodyJumpLabel.Offset - bodyStartIndex);

                            mContext.Push(CompoundStatementContext.If);

                            var condition = mValueStack.Pop();
                            var bodyIfTrue = ParseCompoundStatement();

                            mContext.Pop();

                            //mInstructionIndex = mScript.JumpLabelSectionData[instruction.OperandShort].Offset;

                            // todo: not sure whether to parse the false black as a compound statement or parse it normally
                            // var bodyIfFalse = ParseCompoundStatement();

                            // remove expression that is evaluated in the if condition
                            int index = statements.FindLastIndex( x => x == condition);
                            if (index == -1)
                                throw new Exception();

                            statements.RemoveAt(index);

                            // and place it in the if statement instead
                            //statements.Add(new SelectionStatement(condition, bodyIfTrue, bodyIfFalse));
                            statements.Add(new SelectionStatement(condition, bodyIfTrue, null));
                            

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
            mValueStack = new Stack<ExpressionStatement>();
            mContext = new Stack<CompoundStatementContext>();
            mContext.Push(CompoundStatementContext.Global);

            var tree = new SyntaxTree();

            for (; mInstructionIndex < script.TextSectionData.Count; mInstructionIndex++)
            {
                var instruction = script.TextSectionData[mInstructionIndex];

                switch (instruction.Opcode)
                {
                    case FlowScriptBinaryOpcode.PROC:
                        {
                            mContext.Push(CompoundStatementContext.Procedure);
                            tree.Nodes.Add(new FunctionDefinition(
                                new Identifier(script.ProcedureLabelSectionData[instruction.OperandShort].Name),
                                ParseCompoundStatement())
                            );
                            mContext.Pop();
                        }
                        break;

                    default:
                        throw new Exception();
                }
            }

            return tree;
        }
    }
}
