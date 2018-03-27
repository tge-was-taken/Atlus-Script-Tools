namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class LogicalAndOperator : BinaryExpression, IOperator
    {
        public int Precedence => 13;

        public LogicalAndOperator() : base( ValueKind.Bool )
        {
        }

        public LogicalAndOperator( Expression left, Expression right )
            : base( ValueKind.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) && ({Right})";
        }
    }
}
