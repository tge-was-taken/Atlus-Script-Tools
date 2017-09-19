namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents a message script text token.
    /// </summary>
    public struct MessageScriptTextToken : IMessageScriptLineToken
    {
        /// <summary>
        /// Gets the text contained by this token. This can be a single word or a whole sentence.
        /// </summary>
        public string Text { get; }

        /// <summary>
        /// Constructs a new message script text token with a text value.
        /// </summary>
        /// <param name="text">The text value of the text token/</param>
        public MessageScriptTextToken( string text )
        {
            Text = text;
        }

        /// <summary>
        /// Converts this token to its string representation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return Text;
        }

        /// <summary>
        /// Gets the token type.
        /// </summary>
        MessageScriptTokenType IMessageScriptLineToken.Type => MessageScriptTokenType.Text;
    }
}
