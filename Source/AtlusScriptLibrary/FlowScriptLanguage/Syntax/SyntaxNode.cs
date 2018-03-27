namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public abstract class SyntaxNode
    {
        public SourceInfo SourceInfo { get; internal set; }

        public override string ToString()
        {
            if ( SourceInfo != null )
            {
                return SourceInfo.ToString();
            }

            return string.Empty;    
        }
    }
}
