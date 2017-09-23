namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptParameter : FlowScriptAstNode
    {
        public FlowScriptTypeIdentifier TypeIdentifier { get; set; }

        public FlowScriptIdentifier Identifier { get; set; }

        public override string ToString()
        {
            return $"{TypeIdentifier} {Identifier}";
        }
    }
}