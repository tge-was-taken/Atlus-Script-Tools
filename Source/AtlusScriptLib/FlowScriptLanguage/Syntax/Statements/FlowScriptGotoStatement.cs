namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptGotoStatement : FlowScriptStatement
    {
        public FlowScriptIdentifier LabelIdentifier { get; set; }

        public FlowScriptGotoStatement()
        {
        }

        public FlowScriptGotoStatement( FlowScriptIdentifier labelIdentifier )
        {
            LabelIdentifier = labelIdentifier;
        }

        public override string ToString()
        {
            return $"goto {LabelIdentifier};";
        }
    }
}
