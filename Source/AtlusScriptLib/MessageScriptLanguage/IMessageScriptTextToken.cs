namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Common interface for message script line tokens.
    /// </summary>
    public interface IMessageScriptTextToken
    {
        /// <summary>
        /// Gets the type of token.
        /// </summary>
        MessageScriptTextTokenType Type { get; }
    }
}
