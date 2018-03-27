namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public abstract class UnaryExpression : Expression
    {
        public Expression Operand { get; set; }

        protected UnaryExpression( ValueKind kind ) : base( kind )
        {
        }

        protected UnaryExpression( ValueKind kind, Expression operand ) : base( kind )
        {
            Operand = operand;
        }
    }
}
