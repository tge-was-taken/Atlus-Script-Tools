using System;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib
{
    public class MessageScriptDialogueMessage : IMessageScriptMessage
    {
        public string Identifier { get; }

        public string SpeakerName { get; set; }

        public List<MessageScriptLine> Lines { get; }

        public MessageScriptDialogueMessage(string identifier)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            SpeakerName = null;
            Lines = new List<MessageScriptLine>();
        }

        public MessageScriptDialogueMessage(string identifier, string speakerName)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            SpeakerName = speakerName;
            Lines = new List<MessageScriptLine>();
        }

        public MessageScriptDialogueMessage(string identifier, string speakerName, List<MessageScriptLine> lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            SpeakerName = speakerName;
            Lines = lines ?? throw new ArgumentNullException(nameof(lines));
        }

        public MessageScriptDialogueMessage(string identifier, List<MessageScriptLine> lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            SpeakerName = null;
            Lines = lines;
        }

        public MessageScriptDialogueMessage(string identifier, string speakerName, params MessageScriptLine[] lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            SpeakerName = speakerName;
            Lines = lines.ToList();
        }

        public MessageScriptDialogueMessage(string identifier, params MessageScriptLine[] lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            SpeakerName = null;
            Lines = lines.ToList();
        }

        // IMessageScriptMessage implementation
        MessageScriptMessageType IMessageScriptMessage.Type => MessageScriptMessageType.Dialogue;
    }
}