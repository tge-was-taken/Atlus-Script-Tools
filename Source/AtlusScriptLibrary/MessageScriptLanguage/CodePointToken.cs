namespace AtlusScriptLibrary.MessageScriptLanguage
{
    /// <summary>
    /// Represents a code point token. This maps to a glyph on the game's font.
    /// </summary>
    public struct CodePointToken : IToken
    {
        /// <summary>
        /// Gets the high surrogate byte of the code point.
        /// </summary>
        public byte HighSurrogate { get; }

        /// <summary>
        /// Gets the low surrogate byte of the code point.
        /// </summary>
        public byte LowSurrogate { get; }

        /// <summary>
        /// Constructs a new code point token from a high and low surrogate byte.
        /// </summary>
        /// <param name="high">The high surrogate byte.</param>
        /// <param name="low">The low surrogate byte.</param>
        public CodePointToken( byte high, byte low )
        {
            HighSurrogate = high;
            LowSurrogate = low;
        }

        /// <summary>
        /// Gets the token type of this token.
        /// </summary>
        TokenKind IToken.Kind => TokenKind.CodePoint;

        /// <summary>
        /// Converts this token to its string representation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"[{HighSurrogate:X2} {LowSurrogate:X2}]";
        }
    }
}
