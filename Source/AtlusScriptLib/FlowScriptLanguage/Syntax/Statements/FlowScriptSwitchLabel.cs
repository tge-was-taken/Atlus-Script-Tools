using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptSwitchLabel : FlowScriptSyntaxNode
    {
        public List<FlowScriptStatement> Body { get; set; }

        protected FlowScriptSwitchLabel()
        {
            Body = new List<FlowScriptStatement>();
        }

        protected FlowScriptSwitchLabel( params FlowScriptStatement[] statements )
        {
            Body = statements.ToList();
        }
    }
}