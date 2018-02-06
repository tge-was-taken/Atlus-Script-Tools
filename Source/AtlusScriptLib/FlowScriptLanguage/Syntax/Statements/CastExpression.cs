namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class CastExpression : Expression
    {
        protected CastExpression( ValueKind kind ) : base( kind )
        {
        }
    }
}