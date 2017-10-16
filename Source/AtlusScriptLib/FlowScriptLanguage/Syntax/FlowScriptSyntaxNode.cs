namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptSyntaxNode
    {
        public FlowScriptSourceInfo SourceInfo { get; internal set; }

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
