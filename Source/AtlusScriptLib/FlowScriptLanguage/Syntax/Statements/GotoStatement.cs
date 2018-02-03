namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class GotoStatement : Statement
    {
        public Identifier LabelIdentifier { get; set; }

        public GotoStatement()
        {
        }

        public GotoStatement( Identifier labelIdentifier )
        {
            LabelIdentifier = labelIdentifier;
        }

        public override string ToString()
        {
            return $"goto {LabelIdentifier}";
        }
    }
}
