using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AtlusScriptLib.Shared.Syntax
{
    public class SyntaxTree
    {
        public List<SyntaxNode> Nodes { get; }

        public string SourceFilename { get; }

        public SyntaxTree()
        {
            Nodes = new List<SyntaxNode>();
        }

        public override string ToString()
        {
            return base.ToString();
        }
    }

    public class SyntaxNodeSourceInfo
    {
        public int LineNumber { get; }
        public int CharacterNumber { get; }
    }

    public abstract class SyntaxNode
    {
    }

    // Argument list
    public class FunctionArgumentList : SyntaxNode
    {
        public List<Statement> Arguments { get; }

        public FunctionArgumentList()
        {
            Arguments = new List<Statement>();
        }

        public FunctionArgumentList(List<Statement> arguments)
        {
            Arguments = arguments;
        }

        public FunctionArgumentList(params Statement[] arguments)
        {
            Arguments = arguments.ToList();
        }

        public override string ToString()
        {
            var argsString = string.Empty;

            bool isFirst = true;
            foreach (var item in Arguments)
            {
                if (!isFirst)
                    argsString += ", ";
                else
                    isFirst = false;

                argsString += item.ToString();
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
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append("{\n");

            foreach (var item in Statements)
            {
                var itemString = item.ToString();
                var itemLines = itemString.Split(new char[] { '\r', '\n' });

                foreach (var line in itemLines)
                {
                    stringBuilder.AppendLine("\t" + line);
                }        
            }

            stringBuilder.Append("}");

            return stringBuilder.ToString();
        }
    }

    public abstract class Declaration : Statement
    {
        public Identifier Identifier { get; }

        public Declaration(Identifier identifier)
        {
            Identifier = identifier;
        }

        public override string ToString()
        {
            return Identifier.Name;
        }
    }

    public abstract class Expression : Statement
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

    public class Selection : Statement
    {
        public Expression Condition { get; }
        public CompoundStatement BodyIfTrue { get; }

        public CompoundStatement BodyIfFalse { get; }

        public Selection(Expression condition, CompoundStatement bodyIfTrue, CompoundStatement bodyIfFalse)
        {
            Condition = condition;
            BodyIfTrue = bodyIfTrue;
            BodyIfFalse = bodyIfFalse;
        }

        public override string ToString()
        {
            if (BodyIfFalse == null)
            {
                return $"if ({Condition}) \n{BodyIfTrue}\n";
            }
            else
            {
                return $"if ({Condition}) \n{BodyIfTrue}\n else \n{BodyIfFalse}\n";
            }
        }
    }

    // Declarations
    public enum FunctionDeclarationFlags
    {
        None,
        ReturnTypeVoid,
        ReturnTypeInt,
        ReturnTypeFloat,
    }

    public class FunctionDeclaration : Declaration
    {
        public FunctionDeclarationFlags Flags { get; }

        public FunctionArgumentList ArgumentList { get; }

        public FunctionDeclaration(FunctionDeclarationFlags flags, Identifier identifier, FunctionArgumentList arguments)
            : base(identifier)
        {
            Flags = flags;
            ArgumentList = arguments;
        }

        public FunctionDeclaration(Identifier identifier, FunctionArgumentList arguments)
            : this(FunctionDeclarationFlags.None, identifier, arguments)
        {
        }

        public FunctionDeclaration(Identifier identifier)
            : this(FunctionDeclarationFlags.None, identifier, new FunctionArgumentList())
        {
        }

        public override string ToString()
        {
            if (Flags != FunctionDeclarationFlags.None)
                return $"func {Flags} {Identifier}{ArgumentList}";
            else
                return $"func {Identifier}{ArgumentList}";
        }
    }

    public class FunctionDefinition : FunctionDeclaration
    {
        public CompoundStatement Body { get; }

        public FunctionDefinition(Identifier identifier, FunctionDeclarationFlags flags, FunctionArgumentList arguments, CompoundStatement body)
            : base(flags, identifier, arguments)
        {
            Body = body;
        }

        public FunctionDefinition(Identifier identifier, FunctionArgumentList arguments, CompoundStatement body)
            : base(identifier, arguments)
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
                return $"func {Flags} {Identifier}({ArgumentList})\n{Body}\n";
            else
                return $"func {Identifier}({ArgumentList})\n{Body}\n";
        }
    }

    public enum VariableDeclarationFlags
    {
        None,
        Static,
        TypeInt,
        TypeFloat,
        TypeString
    }

    public class VariableDeclaration : Declaration
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
        public Expression Initializer { get; }

        public VariableDefinition(Identifier identifier, VariableDeclarationFlags flags, Expression initializer)
            : base(identifier, flags)
        {
            Initializer = initializer;
        }

        public VariableDefinition(Identifier identifier, Expression initializer)
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
    public abstract class UnaryExpression : Expression
    {
        public SyntaxNode Operand { get; }

        public UnaryExpression(SyntaxNode operand)
        {
            Operand = operand;
        }
    }

    public abstract class UnaryArithmicExpression : UnaryExpression
    {
        public new Expression Operand => (Expression)base.Operand;

        public UnaryArithmicExpression(Expression operand)
            : base(operand)
        {
        }
    }

    public abstract class BinaryExpression : Expression
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
        public new Expression LeftOperand => (Expression)base.LeftOperand;

        public new Expression RightOperand => (Expression)base.RightOperand;

        public BinaryArithmicExpression(Expression leftOperand, Expression rightOperand)
            : base(leftOperand, rightOperand)
        {
        }
    }

    public interface IOperator
    {
        int Precedence { get; }
    }

    public class FunctionCallOperator : Expression, IOperator
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

        public UnaryMinusOperator(Expression operand)
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

        public UnaryNotOperator(Expression operand)
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

        public BinaryAddOperator(Expression leftOperand, Expression rightOperand)
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

        public BinarySubtractOperator(Expression leftOperand, Expression rightOperand)
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

        public BinaryMultiplyOperator(Expression leftOperand, Expression rightOperand)
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

        public BinaryDivideOperator(Expression leftOperand, Expression rightOperand)
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

        public BinaryLogicalOrOperator(Expression leftOperand, Expression rightOperand)
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

        public BinaryLogicalAndOperator(Expression leftOperand, Expression rightOperand)
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

        public BinaryEqualityOperator(Expression leftOperand, Expression rightOperand)
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

        public BinaryNonEqualityOperator(Expression leftOperand, Expression rightOperand)
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

        public BinaryLessThanOperator(Expression leftOperand, Expression rightOperand)
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

        public BinaryGreaterThanOperator(Expression leftOperand, Expression rightOperand)
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

        public BinaryLessThanOrEqualOperator(Expression leftOperand, Expression rightOperand)
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

        public BinaryGreaterThanOrEqualOperator(Expression leftOperand, Expression rightOperand)
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

        public new Expression RightOperand => (Expression)base.RightOperand;

        public int Precedence => 14;

        public BinaryAssignmentOperator(Identifier leftOperand, Expression rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} = {RightOperand}";
        }
    }

    // Literal expressions
    public abstract class Literal<T> : Expression
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

        public override string ToString()
        {
            return Value + "f";
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
    public class Identifier : Expression
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
        public Expression Expression { get; }

        public ReturnStatement(Expression expression = null)
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
