namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptFunctionDeclaration : FlowScriptDeclaration
    {
        public FlowScriptTypeIdentifier ReturnType { get; }

        public FlowScriptIntLiteral Index { get; }

        public FlowScriptIdentifier Identifier { get; }

        public FlowScriptList<FlowScriptParameter> Parameters { get; }
    }
}
