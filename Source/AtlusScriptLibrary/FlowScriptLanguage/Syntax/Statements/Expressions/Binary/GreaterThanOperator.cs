namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class GreaterThanOperator : BinaryExpression, IOperator
    {
        public int Precedence => 8;

        public GreaterThanOperator() : base( ValueKind.Bool )
        {
        }

        public GreaterThanOperator( Expression left, Expression right )
            : base( ValueKind.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) > ({Right})";
        }
    }
}
