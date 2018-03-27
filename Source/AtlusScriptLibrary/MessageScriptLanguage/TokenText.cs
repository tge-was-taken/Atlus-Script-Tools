using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage
{
    /// <summary>
    /// Represents a single line of text.
    /// </summary>
    public class TokenText : IEnumerable<IToken>
    {
        /// <summary>
        /// Gets the list of tokens contained in this line of text.
        /// </summary>
        public List<IToken> Tokens { get; }

        /// <summary>
        /// Construct a new empty message script line.
        /// </summary>
        public TokenText()
        {
            Tokens = new List<IToken>();
        }

        /// <summary>
        /// Constructs a new message script line with a list of tokens.
        /// </summary>
        /// <param name="tokens">The list of message script tokens.</param>
        public TokenText( List<IToken> tokens )
        {
            Tokens = tokens ?? throw new ArgumentNullException( nameof( tokens ) );
        }

        /// <summary>
        /// Constructs a new message script line with a list of tokens.
        /// </summary>
        /// <param name="tokens">The list of message script tokens.</param>
        public TokenText( params IToken[] tokens )
        {
            Tokens = tokens.ToList();
        }

        /// <summary>
        /// Returns an enumerator that iterates through the tokens in the line.
        /// </summary>
        /// <returns></returns>
        public IEnumerator<IToken> GetEnumerator()
        {
            return ( ( IEnumerable<IToken> )Tokens ).GetEnumerator();
        }

        /// <summary>
        /// Returns an enumerator that iterates through the tokens in the line.
        /// </summary>
        /// <returns></returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return ( ( IEnumerable<IToken> )Tokens ).GetEnumerator();
        }
    }
}
