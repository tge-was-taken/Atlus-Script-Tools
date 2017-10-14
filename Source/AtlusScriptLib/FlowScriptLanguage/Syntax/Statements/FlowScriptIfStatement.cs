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

        public List<FlowScriptStatement> ElseStatements { get; set; }

        public FlowScriptIfStatement()
        {
            ElseStatements = new List<FlowScriptStatement>();
        }

        public override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append( $"if ( {Condition} ) {Body}" );
            if ( ElseStatements.Count > 0 )
            {
                builder.Append( " else " );
                foreach ( var item in ElseStatements )
                {
                    builder.Append( item.ToString() );
                }
            }

            return builder.ToString();
        }
    }
}
