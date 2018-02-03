namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class BoolLiteral : Literal<bool>
    {
        public BoolLiteral( ) : base( ValueKind.Bool )
        {
        }

        public BoolLiteral( bool value ) : base( ValueKind.Bool, value )
        {
        }
    }
}
