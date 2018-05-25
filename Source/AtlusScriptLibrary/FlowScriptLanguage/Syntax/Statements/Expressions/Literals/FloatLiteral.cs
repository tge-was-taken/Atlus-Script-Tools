namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class FloatLiteral : Literal<float>
    {
        public FloatLiteral() : base( ValueKind.Float )
        {
        }

        public FloatLiteral( float value ) : base( ValueKind.Float, value )
        {
        }

        public static implicit operator FloatLiteral( float value ) => new FloatLiteral( value );
    }
}
