using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptSwitchLabel : SyntaxNode
    {
        public List<Statement> Body { get; set; }

        protected FlowScriptSwitchLabel()
        {
            Body = new List<Statement>();
        }

        protected FlowScriptSwitchLabel( params Statement[] statements )
        {
            Body = statements.ToList();
        }
    }
}