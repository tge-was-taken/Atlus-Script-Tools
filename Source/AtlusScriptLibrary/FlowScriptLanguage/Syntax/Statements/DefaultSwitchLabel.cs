namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class DefaultSwitchLabel : FlowScriptSwitchLabel
    {
        public DefaultSwitchLabel()
        {
        }

        public DefaultSwitchLabel( params Statement[] statements )
            : base( statements )
        {
        }

        public override string ToString()
        {
            return "default";
        }
    }
}