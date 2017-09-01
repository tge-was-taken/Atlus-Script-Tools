using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib
{
    /// <summary>
    /// Represents a selection message in a message script.
    /// </summary>
    public class MessageScriptSelectionMessage : IMessageScriptMessage
    {
        /// <summary>
        /// Gets the text identifier of this message.
        /// </summary>
        public string Identifier { get; }

        /// <summary>
        /// Gets the list of lines in this message.
        /// </summary>
        public List<MessageScriptLine> Lines { get; }

        /// <summary>
        /// Constructs a new selection message with just an identifier.
        /// </summary>
        /// <param name="identifier">The text identifier of the message.</param>
        public MessageScriptSelectionMessage(string identifier)
        {
            Identifier = identifier;
            Lines = new List<MessageScriptLine>();
        }

        /// <summary>
        /// Constructs a new selection message with just an identifier.
        /// </summary>
        /// <param name="identifier">The text identifier of the message.</param>
        /// <param name="lines">The list of lines in the message.</param>
        public MessageScriptSelectionMessage(string identifier, List<MessageScriptLine> lines)
        {
            Identifier = identifier;
            Lines = lines;
        }

        /// <summary>
        /// Constructs a new selection message with just an identifier.
        /// </summary>
        /// <param name="identifier">The text identifier of the message.</param>
        /// <param name="lines">The list of lines in the message.</param>
        public MessageScriptSelectionMessage(string identifier, params MessageScriptLine[] lines)
        {
            Identifier = identifier;
            Lines = lines.ToList();
        }

        /// <summary>
        /// Gets the message type.
        /// </summary>
        MessageScriptMessageType IMessageScriptMessage.Type => MessageScriptMessageType.Selection;
    }
}