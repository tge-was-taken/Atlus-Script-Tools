namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public abstract class BinaryExpression : Expression
    {
        public Expression Left { get; set; }

        public Expression Right { get; set; }

        protected BinaryExpression( ValueKind kind ) : base( kind )
        {
        }

        protected BinaryExpression( ValueKind kind, Expression left, Expression right ) : this( kind )
        {
            Left = left;
            Right = right;
        }
    }
}
