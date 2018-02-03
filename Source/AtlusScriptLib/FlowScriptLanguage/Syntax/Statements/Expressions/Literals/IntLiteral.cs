namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class IntLiteral : Literal<int>
    {
        public IntLiteral() : base( ValueKind.Int )
        {
        }

        public IntLiteral( int value ) : base( ValueKind.Int, value )
        {
        }
    }
}
