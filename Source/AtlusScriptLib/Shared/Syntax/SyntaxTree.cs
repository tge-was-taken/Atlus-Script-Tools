using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib.Shared.Syntax
{
    public class SyntaxTree
    {
        public List<SyntaxNode> Nodes { get; }

        public SyntaxTree()
        {
            Nodes = new List<SyntaxNode>();
        }

        public override string ToString()
        {
            return base.ToString();
        }
    }

    public abstract class SyntaxNode
    {
    }

    // Argument list
    public class FunctionArgumentList : SyntaxNode
    {
        public List<ExpressionStatement> Arguments { get; }

        public FunctionArgumentList()
        {
            Arguments = new List<ExpressionStatement>();
        }

        public FunctionArgumentList(List<ExpressionStatement> arguments)
        {
            Arguments = arguments;
        }

        public FunctionArgumentList(params ExpressionStatement[] arguments)
        {
            Arguments = arguments.ToList();
        }

        public override string ToString()
        {
            var argsString = " ";

            foreach (var item in Arguments)
            {
                argsString += item.ToString();
                argsString += " ";
            }

            return $"({argsString})";
        }
    }

    // Statements
    public abstract class Statement : SyntaxNode
    {

    }

    public class CompoundStatement : Statement
    {
        public List<Statement> Statements { get; }

        public CompoundStatement()
        {
            Statements = new List<Statement>();
        }

        public CompoundStatement(List<Statement> statements)
        {
            Statements = statements;
        }

        public CompoundStatement(params Statement[] statements)
        {
            Statements = statements.ToList();
        }

        public override string ToString()
        {
            return Statements.ToString();
        }
    }

    public abstract class DeclarationStatement : Statement
    {
        public Identifier Identifier { get; }

        public DeclarationStatement(Identifier identifier)
        {
            Identifier = identifier;
        }

        public override string ToString()
        {
            return Identifier.Name;
        }
    }

    public abstract class ExpressionStatement : Statement
    {
    }

    public abstract class JumpStatement : Statement
    {
    }

    public class LabeledStatement : Statement
    {
        public Identifier Identifier { get; }

        public Statement Statement { get; }

        public LabeledStatement(Identifier identifier, Statement statement)
        {
            Identifier = identifier;
            Statement = statement;
        }

        public override string ToString()
        {
            if (Statement != null)
                return $"{Identifier}: {Statement}";
            else
                return $"{Identifier}:";
        }
    }

    public class SelectionStatement : Statement
    {
        public ExpressionStatement Condition { get; }
        public CompoundStatement BodyIfTrue { get; }

        public CompoundStatement BodyIfFalse { get; }

        public SelectionStatement(ExpressionStatement condition, CompoundStatement bodyIfTrue, CompoundStatement bodyIfFalse)
        {
            Condition = condition;
            BodyIfTrue = bodyIfTrue;
            BodyIfFalse = bodyIfFalse;
        }

        public override string ToString()
        {
            return  $"if ({Condition}) \n" +
                    $"{{{BodyIfTrue}}} " +
                    $"else " +
                    $"{{{BodyIfFalse}}}";
        }
    }

    // Declarations
    public enum FunctionDeclarationFlags
    {
        None,
    }

    public class FunctionDeclaration : DeclarationStatement
    {
        public FunctionDeclarationFlags Flags { get; }

        public FunctionDeclaration(Identifier identifier, FunctionDeclarationFlags flags)
            : base(identifier)
        {
            Flags = flags;
        }

        public FunctionDeclaration(Identifier identifier)
            : this(identifier, FunctionDeclarationFlags.None)
        {
        }

        public override string ToString()
        {
            if (Flags != FunctionDeclarationFlags.None)
                return $"func {Flags} {Identifier}";
            else
                return $"func {Identifier}";
        }
    }

    public class FunctionDefinition : FunctionDeclaration
    {
        public CompoundStatement Body { get; }

        public FunctionDefinition(Identifier identifier, FunctionDeclarationFlags flags, CompoundStatement body)
            : base(identifier, flags)
        {
            Body = body;
        }

        public FunctionDefinition(Identifier identifier, CompoundStatement body)
            : base(identifier)
        {
            Body = body;
        }

        public override string ToString()
        {
            if (Flags != FunctionDeclarationFlags.None)
                return $"func {Flags} {Identifier} {Body}";
            else
                return $"func {Identifier} {Body}";
        }
    }

    public enum VariableDeclarationFlags
    {
        None,
        TypeInt,
        TypeFloat
    }

    public class VariableDeclaration : DeclarationStatement
    {
        public VariableDeclarationFlags Flags { get; }

        public VariableDeclaration(Identifier identifier, VariableDeclarationFlags flags)
            : base(identifier)
        {
        }

        public override string ToString()
        {
            if (Flags != VariableDeclarationFlags.None)
                return $"var {Flags} {Identifier}";
            else
                return $"var {Identifier}";
        }
    }

    public class VariableDefinition : VariableDeclaration
    {
        public ExpressionStatement Initializer { get; }

        public VariableDefinition(Identifier identifier, VariableDeclarationFlags flags, ExpressionStatement initializer)
            : base(identifier, flags)
        {
            Initializer = initializer;
        }

        public VariableDefinition(Identifier identifier, ExpressionStatement initializer)
            : base(identifier, VariableDeclarationFlags.None)
        {
            Initializer = initializer;
        }

        public override string ToString()
        {
            if (Flags != VariableDeclarationFlags.None)
                return $"var {Flags} {Identifier} = {Initializer}";
            else
                return $"var {Identifier} = {Initializer}";
        }
    }

    // Expressions
    public abstract class UnaryExpression : ExpressionStatement
    {
        public SyntaxNode Operand { get; }

        public UnaryExpression(SyntaxNode operand)
        {
            Operand = operand;
        }
    }

    public abstract class UnaryArithmicExpression : UnaryExpression
    {
        public new ExpressionStatement Operand => (ExpressionStatement)base.Operand;

        public UnaryArithmicExpression(ExpressionStatement operand)
            : base(operand)
        {
        }
    }

    public abstract class BinaryExpression : ExpressionStatement
    {
        public SyntaxNode LeftOperand { get; }
        
        public SyntaxNode RightOperand { get; }

        public BinaryExpression(SyntaxNode leftOperand, SyntaxNode rightOperand)
        {
            LeftOperand = leftOperand;
            RightOperand = rightOperand;
        }
    }

    public abstract class BinaryArithmicExpression : BinaryExpression
    {
        public new ExpressionStatement LeftOperand => (ExpressionStatement)base.LeftOperand;

        public new ExpressionStatement RightOperand => (ExpressionStatement)base.RightOperand;

        public BinaryArithmicExpression(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }
    }

    public interface IOperator
    {
        int Precedence { get; }
    }

    public class FunctionCallOperator : ExpressionStatement, IOperator
    {
        public int Precedence => 1;

        public Identifier Identifier { get; }

        public FunctionArgumentList ArgumentList { get; }

        public FunctionCallOperator(Identifier identifier, FunctionArgumentList argumentList)
        {
            Identifier = identifier;
            ArgumentList = argumentList;
        }

        public FunctionCallOperator(Identifier identifier)
        {
            Identifier = identifier;
            ArgumentList = new FunctionArgumentList();
        }

        public override string ToString()
        {
            return $"{Identifier}{ArgumentList}";
        }
    }

    // Unary expressions - operators
    public class UnaryMinusOperator : UnaryArithmicExpression, IOperator
    {
        public int Precedence => 2;

        public UnaryMinusOperator(ExpressionStatement operand)
            : base(operand)
        {
        }

        public override string ToString()
        {
            return $"-{Operand}";
        }
    }

    public class UnaryNotOperator : UnaryArithmicExpression, IOperator
    {
        public int Precedence => 2;

        public UnaryNotOperator(ExpressionStatement operand)
            : base(operand)
        {
        }

        public override string ToString()
        {
            return $"~{Operand}";
        }
    }

    // Binary expressions - operators
    public class BinaryAddOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 4;

        public BinaryAddOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {         
        }

        public override string ToString()
        {
            return $"{LeftOperand} + {RightOperand}";
        }
    }

    public class BinarySubtractOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 4;

        public BinarySubtractOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} - {RightOperand}";
        }
    }

    public class BinaryMultiplyOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 3;

        public BinaryMultiplyOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} * {RightOperand}";
        }
    }

    public class BinaryDivideOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 4;

        public BinaryDivideOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} / {RightOperand}";
        }
    }

    public class BinaryLogicalOrOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 10;

        public BinaryLogicalOrOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} || {RightOperand}";
        }
    }

    public class BinaryLogicalAndOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 8;

        public BinaryLogicalAndOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} && {RightOperand}";
        }
    }

    public class BinaryEqualityOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 7;

        public BinaryEqualityOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} == {RightOperand}";
        }
    }

    public class BinaryNonEqualityOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 7;

        public BinaryNonEqualityOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} != {RightOperand}";
        }
    }

    public class BinaryLessThanOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 6;

        public BinaryLessThanOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} < {RightOperand}";
        }
    }

    public class BinaryGreaterThanOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 6;

        public BinaryGreaterThanOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} > {RightOperand}";
        }
    }

    public class BinaryLessThanOrEqualOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 6;

        public BinaryLessThanOrEqualOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} =< {RightOperand}";
        }
    }

    public class BinaryGreaterThanOrEqualOperator : BinaryArithmicExpression, IOperator
    {
        public int Precedence => 6;

        public BinaryGreaterThanOrEqualOperator(ExpressionStatement leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} >= {RightOperand}";
        }
    }

    public class BinaryAssignmentOperator : BinaryExpression, IOperator
    {
        public new Identifier LeftOperand => (Identifier)base.LeftOperand;

        public new ExpressionStatement RightOperand => (ExpressionStatement)base.RightOperand;

        public int Precedence => 14;

        public BinaryAssignmentOperator(Identifier leftOperand, ExpressionStatement rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} = {RightOperand}";
        }
    }

    // Literal expressions
    public abstract class Literal<T> : ExpressionStatement
    {
        public T Value { get; }

        public Literal(T value)
        {
            Value = value;
        }

        public override string ToString()
        {
            return $"{Value}";
        }
    }

    public class ShortLiteral : Literal<short>
    {
        public ShortLiteral(short value)
            : base(value)
        {
        }
    }

    public class IntLiteral : Literal<int>
    {
        public IntLiteral(int value)
            : base(value)
        {
        }
    }

    public class FloatLiteral : Literal<float>
    {
        public FloatLiteral(float value)
            : base(value)
        {
        }
    }

    public class StringLiteral : Literal<string>
    {
        public StringLiteral(string value)
            : base(value)
        {
        }
    }

    public class BoolLiteral : Literal<bool>
    {
        public BoolLiteral(bool value)
            : base(value)
        {

        }
    }

    // Identifier expression
    public class Identifier : ExpressionStatement
    {
        public string Name { get; }

        public Identifier(string name)
        {
            Name = name;
        }

        public override string ToString()
        {
            return $"{Name}";
        }
    }

    // jump statements
    public class GotoStatement : JumpStatement
    {
        public Identifier Identifier { get; }

        public GotoStatement(Identifier identifier = null)
        {
            Identifier = identifier;
        }

        public override string ToString()
        {
            return $"goto {Identifier}";
        }
    }

    public class ReturnStatement : JumpStatement
    {
        public ExpressionStatement Expression { get; }

        public ReturnStatement(ExpressionStatement expression = null)
        {
            Expression = expression;
        }

        public override string ToString()
        {
            return $"return {Expression}";
        }
    }

    public class BreakStatement : JumpStatement
    {
        public override string ToString()
        {
            return $"break";
        }
    }
}
