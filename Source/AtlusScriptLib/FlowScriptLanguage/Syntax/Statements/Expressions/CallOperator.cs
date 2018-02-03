using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class CallOperator : Expression, IOperator
    {
        public Identifier Identifier { get; set; }

        public List<Expression> Arguments { get; set; }

        public int Precedence => 2;

        public CallOperator() : base( ValueKind.Unresolved )
        {
            Arguments = new List<Expression>();
        }

        public CallOperator( Identifier identifier, List<Expression> arguments ) : base( ValueKind.Unresolved )
        {
            Identifier = identifier;
            Arguments = arguments;
        }

        public CallOperator( ValueKind valueKind, Identifier identifier, List<Expression> arguments ) : base( valueKind )
        {
            Identifier = identifier;
            Arguments = arguments;
        }

        public CallOperator( Identifier identifier, params Expression[] arguments ) : base( ValueKind.Unresolved )
        {
            Identifier = identifier;
            Arguments = arguments.ToList();
        }

        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
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
