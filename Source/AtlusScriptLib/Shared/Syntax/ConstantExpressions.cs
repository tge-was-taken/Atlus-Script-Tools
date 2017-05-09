using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Shared.Syntax
{
    public abstract class ConstantExpression<T> : Expression
    {
        public T Value { get; }

        public ConstantExpression(T value)
        {
            Value = value;
        }

        public override string ToString()
        {
            return $"{Value}";
        }
    }

    public class ShortConstant : ConstantExpression<short>
    {
        public ShortConstant(short value)
            : base(value)
        {
        }
    }

    public class IntConstant : ConstantExpression<int>
    {
        public IntConstant(int value)
            : base(value)
        {
        }
    }

    public class FloatConstant : ConstantExpression<float>
    {
        public FloatConstant(float value)
            : base(value)
        {
        }

        public override string ToString()
        {
            return Value + "f";
        }
    }

    public class StringConstant : ConstantExpression<string>
    {
        public StringConstant(string value)
            : base(value)
        {
        }
    }

    public class BoolConstant : ConstantExpression<bool>
    {
        public BoolConstant(bool value)
            : base(value)
        {

        }
    }
}
