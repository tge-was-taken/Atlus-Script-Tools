namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents a single newline token.
    /// </summary>
    public class MessageScriptNewLineToken : IMessageScriptTextToken
    {
        /// <summary>
        /// The constant value of a newline token.
        /// </summary>
        public const byte Value = 0x0A;

        /// <summary>
        /// Gets the type of this token.
        /// </summary>
        public MessageScriptTextTokenType Type => MessageScriptTextTokenType.NewLine;

        /// <summary>
        /// Converts this token to its string reprentation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return "<new line>";
        }
    }
}
