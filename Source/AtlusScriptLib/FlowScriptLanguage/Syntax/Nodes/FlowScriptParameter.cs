namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptParameter : FlowScriptSyntaxNode
    {
        public FlowScriptTypeIdentifier TypeIdentifier { get; set; }

        public FlowScriptIdentifier Identifier { get; set; }

        public override string ToString()
        {
            return $"{TypeIdentifier} {Identifier}";
        }
    }
}