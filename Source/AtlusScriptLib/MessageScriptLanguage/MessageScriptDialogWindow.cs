using System;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents a dialog window in a message script.
    /// </summary>
    public class MessageScriptDialogWindow : IMessageScriptWindow
    {
        /// <summary>
        /// Gets the text identifier of this dialog window.
        /// </summary>
        public string Identifier { get; set; }

        /// <summary>
        /// Gets or sets the speaker of this dialog window.
        /// </summary>
        public IMessageScriptSpeaker Speaker { get; set; }

        /// <summary>
        /// Gets the lines contained in this message.
        /// </summary>
        public List<MessageScriptLine> Lines { get; }

        /// <summary>
        /// Constructs a new dialog window with just an identifier.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        public MessageScriptDialogWindow( string identifier )
        {
            Identifier = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = null;
            Lines = new List<MessageScriptLine>();
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier and a speaker.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="speaker">The speaker of the window.</param>
        public MessageScriptDialogWindow( string identifier, IMessageScriptSpeaker speaker )
        {
            Identifier = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = speaker;
            Lines = new List<MessageScriptLine>();
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier, a speaker and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="speaker">The speaker of the window.</param>
        /// <param name="lines">The list of lines of the window.</param>
        public MessageScriptDialogWindow( string identifier, IMessageScriptSpeaker speaker, List<MessageScriptLine> lines )
        {
            Identifier = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = speaker;
            Lines = lines ?? throw new ArgumentNullException( nameof( lines ) );
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="lines">The list of lines of the window.</param>
        public MessageScriptDialogWindow( string identifier, List<MessageScriptLine> lines )
        {
            Identifier = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = null;
            Lines = lines;
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier, a speaker and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="speaker">The speaker of the window.</param>
        /// <param name="lines">The list of lines of the window.</param>
        public MessageScriptDialogWindow( string identifier, IMessageScriptSpeaker speaker, params MessageScriptLine[] lines )
        {
            Identifier = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = speaker;
            Lines = lines.ToList();
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="lines">The list of lines of the window.</param>
        public MessageScriptDialogWindow( string identifier, params MessageScriptLine[] lines )
        {
            Identifier = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = null;
            Lines = lines.ToList();
        }

        /// <summary>
        /// Converts this window to its string representation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"dlg {Identifier} {Speaker}";
        }

        /// <summary>
        /// Gets the message type of this window.
        /// </summary>
        MessageScriptWindowType IMessageScriptWindow.Type => MessageScriptWindowType.Dialogue;
    }
}