namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class BoolLiteral : Literal<bool>
    {
        public BoolLiteral( ) : base( ValueKind.Bool )
        {
        }

        public BoolLiteral( bool value ) : base( ValueKind.Bool, value )
        {
        }

        public static implicit operator BoolLiteral( bool value ) => new BoolLiteral( value );
    }
}
