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

    public class FlowScriptDefaultSwitchLabel : FlowScriptSwitchLabel
    {
        public FlowScriptDefaultSwitchLabel()
        {
        }

        public FlowScriptDefaultSwitchLabel( params FlowScriptStatement[] statements )
            : base( statements )
        {
        }

        public override string ToString()
        {
            return "default";
        }
    }

    public class FlowScriptConditionSwitchLabel : FlowScriptSwitchLabel
    {
        public FlowScriptExpression Condition { get; set; }

        public FlowScriptConditionSwitchLabel()
        {
        }

        public FlowScriptConditionSwitchLabel( FlowScriptExpression condition, params FlowScriptStatement[] statements )
            : base( statements )
        {
            Condition = condition;
        }

        public override string ToString()
        {
            return $"case {Condition}:";
        }
    }
}
