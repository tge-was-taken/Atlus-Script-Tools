namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptParameter : FlowScriptSyntaxNode
    {
        public FlowScriptTypeIdentifier TypeIdentifier { get; set; }

        public FlowScriptIdentifier Identifier { get; set; }

        public FlowScriptParameter()
        {

        }

        public FlowScriptParameter( FlowScriptTypeIdentifier type, FlowScriptIdentifier identifier )
        {
            TypeIdentifier = type;
            Identifier = identifier;
        }

        public override string ToString()
        {
            return $"{TypeIdentifier} {Identifier}";
        }
    }
}