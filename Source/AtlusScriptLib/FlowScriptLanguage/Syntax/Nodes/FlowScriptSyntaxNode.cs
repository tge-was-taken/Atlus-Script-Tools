namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptSyntaxNode
    {
        public FlowScriptSourceInfo SourceInfo { get; internal set; }

        public override string ToString()
        {
            return SourceInfo.ToString();
        }
    }
}
