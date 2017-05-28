using System;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib
{
    public class MessageScriptDialogueMessage : IMessageScriptMessage
    {
        public string Identifier { get; }

        public IMessageScriptDialogueMessageSpeaker Speaker { get; set; }

        public List<MessageScriptLine> Lines { get; }

        public MessageScriptDialogueMessage(string identifier)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = null;
            Lines = new List<MessageScriptLine>();
        }

        public MessageScriptDialogueMessage(string identifier, IMessageScriptDialogueMessageSpeaker speaker)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = speaker;
            Lines = new List<MessageScriptLine>();
        }

        public MessageScriptDialogueMessage(string identifier, IMessageScriptDialogueMessageSpeaker speaker, List<MessageScriptLine> lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = speaker;
            Lines = lines ?? throw new ArgumentNullException(nameof(lines));
        }

        public MessageScriptDialogueMessage(string identifier, List<MessageScriptLine> lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = null;
            Lines = lines;
        }

        public MessageScriptDialogueMessage(string identifier, IMessageScriptDialogueMessageSpeaker speaker, params MessageScriptLine[] lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = speaker;
            Lines = lines.ToList();
        }

        public MessageScriptDialogueMessage(string identifier, params MessageScriptLine[] lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = null;
            Lines = lines.ToList();
        }

        public override string ToString()
        {
            return $"message {Identifier} {Speaker}";
        }

        // IMessageScriptMessage implementation
        MessageScriptMessageType IMessageScriptMessage.Type => MessageScriptMessageType.Dialogue;
    }

    public interface IMessageScriptDialogueMessageSpeaker
    {
        MessageScriptDialogueMessageSpeakerType Type { get; }
    }

    public class MessageScriptDialogueMessageNamedSpeaker : IMessageScriptDialogueMessageSpeaker
    {
        public MessageScriptLine Name { get; }    

        public MessageScriptDialogueMessageNamedSpeaker(MessageScriptLine name)
        {
            Name = name;
        }

        public override string ToString()
        {
            string str = string.Empty;

            if (Name != null && Name.Tokens.Count > 0)
            {
                foreach (var token in Name.Tokens)
                {
                    str += token.ToString() + " ";
                }
            }

            return str;
        }

        MessageScriptDialogueMessageSpeakerType IMessageScriptDialogueMessageSpeaker.Type => MessageScriptDialogueMessageSpeakerType.Named;
    }

    public class MessageScriptDialogueMessageVariablyNamedSpeaker : IMessageScriptDialogueMessageSpeaker
    {
        MessageScriptDialogueMessageSpeakerType IMessageScriptDialogueMessageSpeaker.Type => MessageScriptDialogueMessageSpeakerType.VariablyNamed;

        public override string ToString()
        {
            return "<variable name>";
        }
    }

    public enum MessageScriptDialogueMessageSpeakerType
    {
        Named,
        VariablyNamed,
    }
}