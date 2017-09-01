using System;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib
{
    public class MessageScriptDialogueMessage : IMessageScriptMessage
    {
        /// <summary>
        /// Gets the text identifier of this message.
        /// </summary>
        public string Identifier { get; set; }

        /// <summary>
        /// Gets or sets the speaker of this message.
        /// </summary>
        public IMessageScriptDialogueMessageSpeaker Speaker { get; set; }

        /// <summary>
        /// Gets the list of lines in this message.
        /// </summary>
        public List<MessageScriptLine> Lines { get; }

        /// <summary>
        /// Constructs a new dialogue message with just an identifier.
        /// </summary>
        /// <param name="identifier">The identifier of the message.</param>
        public MessageScriptDialogueMessage(string identifier)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = null;
            Lines = new List<MessageScriptLine>();
        }

        /// <summary>
        /// Constructs a new dialogue message with an identifier and a speaker.
        /// </summary>
        /// <param name="identifier">The identifier of the message.</param>
        /// <param name="speaker">The speaker of the message.</param>
        public MessageScriptDialogueMessage(string identifier, IMessageScriptDialogueMessageSpeaker speaker)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = speaker;
            Lines = new List<MessageScriptLine>();
        }

        /// <summary>
        /// Constructs a new dialogue message with an identifier, a speaker and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the message.</param>
        /// <param name="speaker">The speaker of the message.</param>
        /// <param name="lines">The list of lines of the message.</param>
        public MessageScriptDialogueMessage(string identifier, IMessageScriptDialogueMessageSpeaker speaker, List<MessageScriptLine> lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = speaker;
            Lines = lines ?? throw new ArgumentNullException(nameof(lines));
        }

        /// <summary>
        /// Constructs a new dialogue message with an identifier and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the message.</param>
        /// <param name="lines">The list of lines of the message.</param>
        public MessageScriptDialogueMessage(string identifier, List<MessageScriptLine> lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = null;
            Lines = lines;
        }

        /// <summary>
        /// Constructs a new dialogue message with an identifier, a speaker and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the message.</param>
        /// <param name="speaker">The speaker of the message.</param>
        /// <param name="lines">The list of lines of the message.</param>
        public MessageScriptDialogueMessage(string identifier, IMessageScriptDialogueMessageSpeaker speaker, params MessageScriptLine[] lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = speaker;
            Lines = lines.ToList();
        }

        /// <summary>
        /// Constructs a new dialogue message with an identifier and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the message.</param>
        /// <param name="lines">The list of lines of the message.</param>
        public MessageScriptDialogueMessage(string identifier, params MessageScriptLine[] lines)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            Speaker = null;
            Lines = lines.ToList();
        }

        /// <summary>
        /// Converts this message to its string representation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"dlg {Identifier} {Speaker}";
        }

        /// <summary>
        /// Gets the message type of this message.
        /// </summary>
        MessageScriptMessageType IMessageScriptMessage.Type => MessageScriptMessageType.Dialogue;
    }

    /// <summary>
    /// Common interface for dialogue message speakers.
    /// </summary>
    public interface IMessageScriptDialogueMessageSpeaker
    {
        /// <summary>
        /// Gets the speaker type.
        /// </summary>
        MessageScriptDialogueMessageSpeakerType Type { get; }
    }

    /// <summary>
    /// Represents a named dialogue message speaker.
    /// </summary>
    public class MessageScriptDialogueMessageNamedSpeaker : IMessageScriptDialogueMessageSpeaker
    {
        /// <summary>
        /// Gets the name of the speaker.
        /// </summary>
        public MessageScriptLine Name { get; }    

        /// <summary>
        /// Constructs a new speaker.
        /// </summary>
        /// <param name="name">The name of the speaker.</param>
        public MessageScriptDialogueMessageNamedSpeaker(MessageScriptLine name)
        {
            Name = name;
        }

        /// <summary>
        /// Converts this speaker to its string representation.
        /// </summary>
        /// <returns></returns>
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

        /// <summary>
        /// Gets the speaker type.
        /// </summary>
        MessageScriptDialogueMessageSpeakerType IMessageScriptDialogueMessageSpeaker.Type => MessageScriptDialogueMessageSpeakerType.Named;
    }

    public class MessageScriptDialogueMessageVariablyNamedSpeaker : IMessageScriptDialogueMessageSpeaker
    {
        /// <summary>
        /// Gets the index of the speaker name variable.
        /// </summary>
        public int Index { get; }

        /// <summary>
        /// Constructs a new variable named dialogue message speaker.
        /// </summary>
        /// <param name="index">The idnex of the speaker name variable.</param>
        public MessageScriptDialogueMessageVariablyNamedSpeaker(int index = 0)
        {
            Index = index;
        }

        /// <summary>
        /// Converts this speaker to its string representation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"<variable name {Index}>";
        }

        /// <summary>
        /// Gets the speaker type.
        /// </summary>
        MessageScriptDialogueMessageSpeakerType IMessageScriptDialogueMessageSpeaker.Type => MessageScriptDialogueMessageSpeakerType.VariablyNamed;
    }

    /// <summary>
    /// Represents the dialogue message speaker types.
    /// </summary>
    public enum MessageScriptDialogueMessageSpeakerType
    {
        Named,
        VariablyNamed,
    }
}