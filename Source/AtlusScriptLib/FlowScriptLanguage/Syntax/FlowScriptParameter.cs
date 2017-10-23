namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptParameter : FlowScriptSyntaxNode
    {
        public FlowScriptTypeIdentifier Type { get; set; }

        public FlowScriptIdentifier Identifier { get; set; }

        public FlowScriptParameter()
        {

        }

        public FlowScriptParameter( FlowScriptTypeIdentifier type, FlowScriptIdentifier identifier )
        {
            Type = type;
            Identifier = identifier;
        }

        public override string ToString()
        {
            return $"{Type} {Identifier}";
        }
    }
}