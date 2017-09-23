namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptImport : FlowScriptAstNode
    {
        public string CompilationUnitFileName { get; set; }

        public override string ToString()
        {
            return $"import \"{CompilationUnitFileName}\"";
        }
    }
}