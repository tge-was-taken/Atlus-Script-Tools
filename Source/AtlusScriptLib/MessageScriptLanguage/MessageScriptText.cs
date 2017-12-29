using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents a single line of text.
    /// </summary>
    public class MessageScriptText : IEnumerable<IMessageScriptTextToken>
    {
        /// <summary>
        /// Gets the list of tokens contained in this line of text.
        /// </summary>
        public List<IMessageScriptTextToken> Tokens { get; }

        /// <summary>
        /// Construct a new empty message script line.
        /// </summary>
        public MessageScriptText()
        {
            Tokens = new List<IMessageScriptTextToken>();
        }

        /// <summary>
        /// Constructs a new message script line with a list of tokens.
        /// </summary>
        /// <param name="tokens">The list of message script tokens.</param>
        public MessageScriptText( List<IMessageScriptTextToken> tokens )
        {
            Tokens = tokens ?? throw new ArgumentNullException( nameof( tokens ) );
        }

        /// <summary>
        /// Constructs a new message script line with a list of tokens.
        /// </summary>
        /// <param name="tokens">The list of message script tokens.</param>
        public MessageScriptText( params IMessageScriptTextToken[] tokens )
        {
            Tokens = tokens.ToList();
        }

        /// <summary>
        /// Returns an enumerator that iterates through the tokens in the line.
        /// </summary>
        /// <returns></returns>
        public IEnumerator<IMessageScriptTextToken> GetEnumerator()
        {
            return ( ( IEnumerable<IMessageScriptTextToken> )Tokens ).GetEnumerator();
        }

        /// <summary>
        /// Returns an enumerator that iterates through the tokens in the line.
        /// </summary>
        /// <returns></returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return ( ( IEnumerable<IMessageScriptTextToken> )Tokens ).GetEnumerator();
        }
    }
}
