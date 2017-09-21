namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptAstSourceInfo
    {
        public int LineIndex { get; }

        public int CharacterIndex { get; }

        public string FileName { get; }

        internal FlowScriptAstSourceInfo( int lineIndex, int characterIndex, string fileName )
        {
            LineIndex = lineIndex;
            CharacterIndex = characterIndex;
            FileName = fileName;
        }
    }
}