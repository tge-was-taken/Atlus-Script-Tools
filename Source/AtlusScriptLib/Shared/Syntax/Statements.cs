using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Shared.Syntax
{
    public abstract class Statement : SyntaxNode
    {

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
            else if (BodyIfTrue == null && BodyIfFalse != null)
            {
                return $"if ({Condition}) \n{{}}\n \n{BodyIfTrue}\n";
            }
            else
            {
                return $"if ({Condition}) \n{BodyIfTrue}\n else \n{BodyIfFalse}\n";
            }
        }
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
}
