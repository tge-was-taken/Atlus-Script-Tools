namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class LogicalOrOperator : BinaryExpression, IOperator
    {
        public int Precedence => 14;

        public LogicalOrOperator() : base( ValueKind.Bool )
        {
        }

        public LogicalOrOperator( Expression left, Expression right )
            : base( ValueKind.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) || ({Right})";
        }
    }
}
