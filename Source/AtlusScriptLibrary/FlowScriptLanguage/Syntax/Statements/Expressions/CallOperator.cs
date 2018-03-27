using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class CallOperator : Expression, IOperator
    {
        public Identifier Identifier { get; set; }

        public List<Argument> Arguments { get; set; }

        public int Precedence => 2;

        public CallOperator() : base( ValueKind.Unresolved )
        {
            Arguments = new List<Argument>();
        }

        public CallOperator( Identifier identifier, List<Argument> arguments ) : base( ValueKind.Unresolved )
        {
            Identifier = identifier;
            Arguments = arguments;
        }

        public CallOperator( ValueKind valueKind, Identifier identifier, List<Argument> arguments ) : base( valueKind )
        {
            Identifier = identifier;
            Arguments = arguments;
        }

        public CallOperator( Identifier identifier, params Argument[] arguments ) : base( ValueKind.Unresolved )
        {
            Identifier = identifier;
            Arguments = arguments.ToList();
        }

        public override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append( Identifier );
            builder.Append( "(" );

            if ( Arguments.Count > 0 )
                builder.Append( Arguments[0] );

            for ( int i = 1; i < Arguments.Count; i++ )
            {
                builder.Append( $", {Arguments[i]}" );
            }

            builder.Append( ")" );

            return builder.ToString();
        }
    }
}
