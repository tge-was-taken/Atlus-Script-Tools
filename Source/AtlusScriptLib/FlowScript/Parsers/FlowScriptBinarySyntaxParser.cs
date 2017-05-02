using System.Collections.Generic;
using System;

using AtlusScriptLib.Shared.Syntax;

namespace AtlusScriptLib.FlowScript.Parsers
{
    public class FlowScriptBinarySyntaxParser
    {
        private FlowScriptBinary mScript;
        private int mInstructionIndex;
        private Stack<ExpressionStatement> mValueStack;

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

        private CompoundStatement ParseCompoundStatement(int maxLength)
        {
            // for compound statement construction later
            var statements = new List<Statement>();

            // we're going to loop until we find an end instruction
            bool endFound = false;

            while (!endFound)
            {
                var instruction = mScript.TextSectionData[++mInstructionIndex];

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
                        mValueStack.Push(new IntLiteral(0)); // TODO: implement using COMM function table
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
                            statements.Add(new FunctionCallOperator(
                                new Identifier("__comm"),
                                new FunctionArgumentList(new IntLiteral(instruction.OperandShort))
                            ));
                        }
                        break;

                    case FlowScriptBinaryOpcode.END:
                        {
                            endFound = true;
                            statements.Add(new ReturnStatement());
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
                        {
                            var node = new BinaryAddOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.SUB:
                        {
                            var node = new BinarySubtractOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.MUL:
                        {
                            var node = new BinaryMultiplyOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.DIV:
                        {
                            var node = new BinaryDivideOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.MINUS:
                        {
                            var node = new UnaryMinusOperator(mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.NOT:
                        {
                            var node = new BinaryNotOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.OR:
                        {
                            var node = new BinaryOrOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.AND:
                        {
                            var node = new BinaryAndOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.EQ:
                        {
                            var node = new BinaryEqualityOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.NEQ:
                        {
                            var node = new BinaryNonEqualityOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.S:
                        {
                            var node = new BinaryLessThanOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.L:
                        {
                            var node = new BinaryGreaterThanOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.SE:
                        {
                            var node = new BinaryLessThanOrEqualOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.LE:
                        {
                            var node = new BinaryGreaterThanOrEqualOperator(mValueStack.Pop(), mValueStack.Pop());
                            statements.Add(node);
                            mValueStack.Push(node);
                        }
                        break;

                    case FlowScriptBinaryOpcode.IF:
                        {
                            var falseBodyJumpLabel = mScript.JumpLabelSectionData[instruction.OperandShort];
                            int bodyStartIndex = mInstructionIndex + 1;
                            int bodyLength = (int)(falseBodyJumpLabel.Offset - bodyStartIndex);

                            statements.Add(new SelectionStatement(mValueStack.Pop(), ParseCompoundStatement(bodyLength)));
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

                // check if we have reached the max length of the compound statement
                // primarily used to parse the if statement body properly
                if (--maxLength == 0)
                    endFound = true;
            }

            return new CompoundStatement(statements);
        }

        public SyntaxTree Parse(FlowScriptBinary script)
        {
            mScript = script;
            mInstructionIndex = 0;
            mValueStack = new Stack<ExpressionStatement>();

            var tree = new SyntaxTree();

            for (int mInstructionIndex = 0; mInstructionIndex < script.TextSectionData.Count; mInstructionIndex++)
            {
                var instruction = script.TextSectionData[mInstructionIndex];

                switch (instruction.Opcode)
                {
                    case FlowScriptBinaryOpcode.PROC:
                        {
                            tree.Nodes.Add(new FunctionDefinition(
                                new Identifier(script.ProcedureLabelSectionData[instruction.OperandShort].Name),
                                ParseCompoundStatement(script.TextSectionData.Count - (mInstructionIndex + 1)))
                            );
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
