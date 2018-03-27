namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class MultiplicationOperator : BinaryExpression, IOperator
    {
        public int Precedence => 5;

        public MultiplicationOperator() : base( ValueKind.Unresolved )
        {
        }

        public MultiplicationOperator( Expression left, Expression right )
            : base( ValueKind.Unresolved, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) * ({Right})";
        }
    }
}
