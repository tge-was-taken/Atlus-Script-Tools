namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
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
}