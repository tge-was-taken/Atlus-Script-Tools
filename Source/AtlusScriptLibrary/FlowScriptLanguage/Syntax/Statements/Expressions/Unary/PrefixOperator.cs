namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class PrefixOperator : UnaryExpression, IOperator
    {
        public int Precedence => 3;

        public PrefixOperator() : base( ValueKind.Unresolved )
        {
        }

        public PrefixOperator( Expression operand ) : base( ValueKind.Unresolved, operand )
        {

        }

        public PrefixOperator( ValueKind kind, Expression operand ) : base( kind, operand )
        {
        }
    }
}
