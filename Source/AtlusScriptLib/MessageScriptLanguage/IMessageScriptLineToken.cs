namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Common interface for message script line tokens.
    /// </summary>
    public interface IMessageScriptLineToken
    {
        /// <summary>
        /// Gets the type of token.
        /// </summary>
        MessageScriptTokenType Type { get; }
    }
}
