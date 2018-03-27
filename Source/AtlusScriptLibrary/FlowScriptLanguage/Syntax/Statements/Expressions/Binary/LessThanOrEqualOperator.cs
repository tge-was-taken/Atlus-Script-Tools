namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class LessThanOrEqualOperator : BinaryExpression, IOperator
    {
        public int Precedence => 8;

        public LessThanOrEqualOperator() : base( ValueKind.Bool )
        {
        }

        public LessThanOrEqualOperator( Expression left, Expression right )
            : base( ValueKind.Bool, left, right )
        {

        }


        public override string ToString()
        {
            return $"({Left}) <= ({Right})";
        }
    }
}
