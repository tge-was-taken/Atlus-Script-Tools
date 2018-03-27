namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class GreaterThanOrEqualOperator : BinaryExpression, IOperator
    {
        public int Precedence => 8;

        public GreaterThanOrEqualOperator() : base( ValueKind.Bool )
        {
        }

        public GreaterThanOrEqualOperator( Expression left, Expression right )
            : base( ValueKind.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) >= ({Right})";
        }
    }
}
