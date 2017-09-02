using System;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib
{
    /// <summary>
    /// Represents a single line of text.
    /// </summary>
    public class MessageScriptLine
    {
        /// <summary>
        /// Gets the list of tokens contained in this line of text.
        /// </summary>
        public List<IMessageScriptLineToken> Tokens { get; }

        /// <summary>
        /// Construct a new empty message script line.
        /// </summary>
        public MessageScriptLine()
        {
            Tokens = new List<IMessageScriptLineToken>();
        }

        /// <summary>
        /// Constructs a new message script line with a list of tokens.
        /// </summary>
        /// <param name="tokens">The list of message script tokens.</param>
        public MessageScriptLine( List<IMessageScriptLineToken> tokens )
        {
            Tokens = tokens ?? throw new ArgumentNullException( nameof( tokens ) );
        }

        /// <summary>
        /// Constructs a new message script line with a list of tokens.
        /// </summary>
        /// <param name="tokens">The list of message script tokens.</param>
        public MessageScriptLine( params IMessageScriptLineToken[] tokens )
        {
            Tokens = tokens.ToList();
        }
    }
}
