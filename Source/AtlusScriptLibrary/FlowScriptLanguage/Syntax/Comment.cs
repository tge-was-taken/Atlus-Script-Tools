namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax;

public class Comment : Statement
{
    public Comment(string content, bool inline)
    {
        Content = content;
        Inline = inline;
    }

    public string Content { get; }
    public bool Inline { get; }
}
