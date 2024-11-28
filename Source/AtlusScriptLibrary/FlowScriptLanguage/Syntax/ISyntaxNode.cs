namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public interface ISyntaxNode
    {
        SourceInfo SourceInfo { get; }

        string ToString();
    }
}