namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents a message script value token.
    /// </summary>
    public struct MessageScriptStringToken : IMessageScriptTextToken
    {
        /// <summary>
        /// Gets the value contained by this token. This can be a single word or a whole sentence.
        /// </summary>
        public string Value { get; }

        /// <summary>
        /// Constructs a new message script value token with a value value.
        /// </summary>
        /// <param name="value">The value value of the value token/</param>
        public MessageScriptStringToken( string value )
        {
            Value = value;
        }

        /// <summary>
        /// Converts this token to its string representation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return Value;
        }

        /// <summary>
        /// Gets the token type.
        /// </summary>
        MessageScriptTextTokenType IMessageScriptTextToken.Type => MessageScriptTextTokenType.String;
    }
}
