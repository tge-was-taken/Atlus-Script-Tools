using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptCallOperator : FlowScriptExpression, IFlowScriptOperator
    {
        public FlowScriptIdentifier Identifier { get; set; }

        public List<FlowScriptExpression> Arguments { get; set; }

        public int Precedence => 2;

        public FlowScriptCallOperator() : base( FlowScriptValueType.Unresolved )
        {
            Arguments = new List<FlowScriptExpression>();
        }

        public FlowScriptCallOperator( FlowScriptIdentifier identifier, params FlowScriptExpression[] arguments ) : base( FlowScriptValueType.Unresolved )
        {
            Identifier = identifier;
            Arguments = arguments.ToList();
        }

        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append( Identifier.ToString() );
            builder.Append( "(" );

            if ( Arguments.Count > 0 )
                builder.Append( Arguments[0].ToString() );

            for ( int i = 1; i < Arguments.Count; i++ )
            {
                builder.Append( $", {Arguments[i].ToString()}" );
            }

            builder.Append( ")" );

            return builder.ToString();
        }
    }
}
