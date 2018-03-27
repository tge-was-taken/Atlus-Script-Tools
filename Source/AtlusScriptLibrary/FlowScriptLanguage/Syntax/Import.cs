namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class Import : SyntaxNode
    {
        public string CompilationUnitFileName { get; set; }

        public Import()
        {

        }

        public Import( string filepath )
        {
            CompilationUnitFileName = filepath;
        }

        public override string ToString()
        {
            return $"import \"{CompilationUnitFileName}\"";
        }
    }
}