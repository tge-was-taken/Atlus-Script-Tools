using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptIfStatement : FlowScriptStatement
    {
        public FlowScriptExpression Condition { get; set; }

        public FlowScriptCompoundStatement Body { get; set; }

        public FlowScriptCompoundStatement ElseBody { get; set; }

        public FlowScriptIfStatement()
        {
        }

        public override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append( $"if ( {Condition} ) {Body}" );
            if ( ElseBody != null )
            {
                builder.Append( $" else {ElseBody}" );
            }

            return builder.ToString();
        }
    }
}
