namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class StringLiteral : Literal<string>
    {
        public StringLiteral() : base( ValueKind.String )
        {
        }

        public StringLiteral( string value ) : base( ValueKind.String, value )
        {
        }

        public static implicit operator StringLiteral( string value ) => new StringLiteral( value );

        public override string ToString()
        {
            return $"\"{Value}\"";
        }
    }
}
