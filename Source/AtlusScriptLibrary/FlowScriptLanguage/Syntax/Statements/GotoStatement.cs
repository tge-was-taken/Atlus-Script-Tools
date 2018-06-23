namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class GotoStatement : Statement
    {
        public Expression Label { get; set; }

        public GotoStatement()
        {
        }

        public GotoStatement( Expression label )
        {
            Label = label;
        }

        public override string ToString()
        {
            return $"goto {Label}";
        }
    }
}
