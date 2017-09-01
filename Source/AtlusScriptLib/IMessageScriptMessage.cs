using System.Collections.Generic;

namespace AtlusScriptLib
{
    /// <summary>
    /// Common interface for message script messages.
    /// </summary>
    public interface IMessageScriptMessage
    {
        /// <summary>
        /// Gets the message type.
        /// </summary>
        MessageScriptMessageType Type { get; }

        /// <summary>
        /// Gets the text identifier of this message.
        /// </summary>
        string Identifier { get; }

        /// <summary>
        /// Gets the list of lines in this message.
        /// </summary>
        List<MessageScriptLine> Lines { get; }
    }
}