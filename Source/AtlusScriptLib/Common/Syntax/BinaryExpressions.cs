using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.Syntax
{
    public abstract class BinaryExpression : Expression
    {
        public Expression LeftOperand { get; }

        public Expression RightOperand { get; }

        public BinaryExpression(Expression leftOperand, Expression rightOperand)
        {
            LeftOperand = leftOperand;
            RightOperand = rightOperand;
        }
    }

    public class BinaryMultiplyOperator : BinaryExpression, IOperator
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

    // Binary expressions - operators
    public class BinaryAddOperator : BinaryExpression, IOperator
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

    public class BinarySubtractOperator : BinaryExpression, IOperator
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

    public class BinaryDivideOperator : BinaryExpression, IOperator
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

    public class BinaryGreaterThanOperator : BinaryExpression, IOperator
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

    public class BinaryGreaterThanOrEqualOperator : BinaryExpression, IOperator
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

    public class BinaryLessThanOrEqualOperator : BinaryExpression, IOperator
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

    public class BinaryLessThanOperator : BinaryExpression, IOperator
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

    public class BinaryEqualityOperator : BinaryExpression, IOperator
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

    public class BinaryNonEqualityOperator : BinaryExpression, IOperator
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

    public class BinaryLogicalAndOperator : BinaryExpression, IOperator
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

    public class BinaryLogicalOrOperator : BinaryExpression, IOperator
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

    public class BinaryAssignmentOperator : BinaryExpression, IOperator
    {
        public int Precedence => 14;

        public BinaryAssignmentOperator(Expression leftOperand, Expression rightOperand)
            : base(leftOperand, rightOperand)
        {
        }

        public override string ToString()
        {
            return $"{LeftOperand} = {RightOperand}";
        }
    }
}
