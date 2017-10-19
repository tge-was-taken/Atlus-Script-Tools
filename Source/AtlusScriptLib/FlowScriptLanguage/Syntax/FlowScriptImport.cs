namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptImport : FlowScriptSyntaxNode
    {
        public string CompilationUnitFileName { get; set; }

        public FlowScriptImport()
        {

        }

        public FlowScriptImport( string filepath )
        {
            CompilationUnitFileName = filepath;
        }

        public override string ToString()
        {
            return $"import \"{CompilationUnitFileName}\"";
        }
    }
}