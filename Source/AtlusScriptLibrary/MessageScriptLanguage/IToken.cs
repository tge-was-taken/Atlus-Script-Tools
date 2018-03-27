namespace AtlusScriptLibrary.MessageScriptLanguage
{
    /// <summary>
    /// Common interface for message script line tokens.
    /// </summary>
    public interface IToken
    {
        /// <summary>
        /// Gets the type of token.
        /// </summary>
        TokenKind Kind { get; }
    }
}
