using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptSwitchStatement : FlowScriptStatement
    {
        public FlowScriptExpression SwitchOn { get; set; }

        public List<FlowScriptSwitchLabel> Labels { get; set; }

        public FlowScriptSwitchStatement()
        {
            Labels = new List<FlowScriptSwitchLabel>();
        }

        public FlowScriptSwitchStatement( FlowScriptExpression switchOn, params FlowScriptSwitchLabel[] labels )
        {
            SwitchOn = switchOn;
            Labels = labels.ToList();
        }

        public override string ToString()
        {
            return $"switch ( {SwitchOn} ) {{ ... }}";
        }
    }
}
