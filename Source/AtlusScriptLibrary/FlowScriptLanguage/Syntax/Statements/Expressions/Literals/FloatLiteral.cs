using System;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class FloatLiteral : Literal<float>, IEquatable<FloatLiteral>
    {
        public FloatLiteral() : base( ValueKind.Float )
        {
        }

        public FloatLiteral( float value ) : base( ValueKind.Float, value )
        {
        }

        public bool Equals( FloatLiteral other )
        {
            return Value == other?.Value;
        }

        public static implicit operator FloatLiteral( float value ) => new FloatLiteral( value );
    }
}
