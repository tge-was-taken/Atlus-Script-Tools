namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class ConditionSwitchLabel : FlowScriptSwitchLabel
    {
        public Expression Condition { get; set; }

        public ConditionSwitchLabel()
        {
        }

        public ConditionSwitchLabel( Expression condition, params Statement[] statements )
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