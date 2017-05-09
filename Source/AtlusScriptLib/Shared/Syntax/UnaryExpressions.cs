using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Shared.Syntax
{
    public abstract class UnaryExpression : Expression
    {
        public Expression Operand { get; }

        public UnaryExpression(Expression operand)
        {
            Operand = operand;
        }
    }

    public class UnaryMinusOperator : UnaryExpression, IOperator
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

    public class UnaryNotOperator : UnaryExpression, IOperator
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
}
