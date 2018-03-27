using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class 
        SwitchStatement : Statement
    {
        public Expression SwitchOn { get; set; }

        public List<FlowScriptSwitchLabel> Labels { get; set; }

        public SwitchStatement()
        {
            Labels = new List<FlowScriptSwitchLabel>();
        }

        public SwitchStatement( Expression switchOn, params FlowScriptSwitchLabel[] labels )
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
