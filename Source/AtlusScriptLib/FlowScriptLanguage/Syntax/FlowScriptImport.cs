namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptImport : FlowScriptSyntaxNode
    {
        public string CompilationUnitFileName { get; set; }

        public override string ToString()
        {
            return $"import \"{CompilationUnitFileName}\"";
        }
    }
}