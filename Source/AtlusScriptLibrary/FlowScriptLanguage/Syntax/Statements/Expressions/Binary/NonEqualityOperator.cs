namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class NonEqualityOperator : BinaryExpression, IOperator
    {
        public int Precedence => 9;

        public NonEqualityOperator() : base( ValueKind.Bool )
        {
        }

        public NonEqualityOperator( Expression left, Expression right )
            : base( ValueKind.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) != ({Right})";
        }
    }
}
