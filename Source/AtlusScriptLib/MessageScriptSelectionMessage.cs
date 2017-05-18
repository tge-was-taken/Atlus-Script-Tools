using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib
{
    public class MessageScriptSelectionMessage : IMessageScriptMessage
    {
        public string Identifier { get; }

        public List<MessageScriptLine> Lines { get; }

        public MessageScriptSelectionMessage(string identifier)
        {
            Identifier = identifier;
            Lines = new List<MessageScriptLine>();
        }

        public MessageScriptSelectionMessage(string identifier, List<MessageScriptLine> lines)
        {
            Identifier = identifier;
            Lines = lines;
        }

        public MessageScriptSelectionMessage(string identifier, params MessageScriptLine[] lines)
        {
            Identifier = identifier;
            Lines = lines.ToList();
        }

        // IMessageScriptMessage implementation
        MessageScriptMessageType IMessageScriptMessage.Type => MessageScriptMessageType.Selection;
    }
}