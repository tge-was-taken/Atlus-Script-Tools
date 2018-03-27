namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class SourceInfo
    {
        public int Line { get; }

        public int Column { get; }

        public string FileName { get; }

        internal SourceInfo( int lineIndex, int characterIndex, string fileName )
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