namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class DivisionOperator : BinaryExpression, IOperator
    {
        public int Precedence => 5;

        public DivisionOperator() : base( ValueKind.Unresolved )
        {
        }

        public DivisionOperator( Expression left, Expression right )
            : base( ValueKind.Unresolved, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) / ({Right})";
        }
    }
}
