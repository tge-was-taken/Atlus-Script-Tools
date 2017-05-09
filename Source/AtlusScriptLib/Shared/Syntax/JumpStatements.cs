using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Shared.Syntax
{
    public abstract class JumpStatement : Statement
    {
    }

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
