namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class LessThanOperator : BinaryExpression, IOperator
    {
        public int Precedence => 8;

        public LessThanOperator() : base( ValueKind.Bool )
        {
        }

        public LessThanOperator( Expression left, Expression right )
            : base( ValueKind.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) < ({Right})";
        }
    }
}
