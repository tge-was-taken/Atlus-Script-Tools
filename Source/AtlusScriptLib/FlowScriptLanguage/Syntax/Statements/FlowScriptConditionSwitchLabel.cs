namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
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