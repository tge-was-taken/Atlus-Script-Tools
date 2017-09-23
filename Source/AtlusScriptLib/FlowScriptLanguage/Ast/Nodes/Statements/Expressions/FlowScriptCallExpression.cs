using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptCallExpression : FlowScriptExpression
    {
        public FlowScriptIdentifier Identifier { get; set; }

        public List<FlowScriptExpression> Arguments { get; set; }

        public FlowScriptCallExpression() : base( FlowScriptValueType.Unresolved )
        {
            Arguments = new List<FlowScriptExpression>();
        }

        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append( Identifier.ToString() );
            builder.Append( '(' );

            if ( Arguments.Count > 0 )
                builder.Append( Arguments[0].ToString() );

            for ( int i = 1; i < Arguments.Count; i++ )
            {
                builder.Append( $", {Arguments[i].ToString()}" );
            }

            builder.Append( ')' );

            return builder.ToString();
        }
    }
}
