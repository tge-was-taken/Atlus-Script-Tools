namespace AtlusScriptLib.Shared
{
    public class SourceFileInfo
    {
        public string FileName { get; }

        public int LineNumber { get; }

        public int CharacterNumber { get; }

        public SourceFileInfo(string fileName, int lineNumber, int characterNumber)
        {
            FileName = fileName;
            LineNumber = lineNumber;
            CharacterNumber = characterNumber;
        }
    }
}
