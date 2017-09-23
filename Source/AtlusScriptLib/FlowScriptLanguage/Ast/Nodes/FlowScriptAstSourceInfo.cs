namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptAstSourceInfo
    {
        public int Line { get; }

        public int Column { get; }

        public string FileName { get; }

        internal FlowScriptAstSourceInfo( int lineIndex, int characterIndex, string fileName )
        {
            Line = lineIndex;
            Column = characterIndex;
            FileName = fileName;
        }

        public override string ToString()
        {
            return $"{FileName} ({Line}:{Column})";
        }
    }
}