using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents a selection window in a message script.
    /// </summary>
    public sealed class MessageScriptSelectionWindow : IMessageScriptWindow
    {
        /// <summary>
        /// Gets the text identifier of this window.
        /// </summary>
        public string Identifier { get; set; }

        /// <summary>
        /// Gets the lines contained in this window.
        /// </summary>
        public List<MessageScriptText> Lines { get; }

        /// <summary>
        /// Constructs a new selection window with just an identifier.
        /// </summary>
        /// <param name="identifier">The text identifier of the window.</param>
        public MessageScriptSelectionWindow( string identifier )
        {
            Identifier = identifier;
            Lines = new List<MessageScriptText>();
        }

        /// <summary>
        /// Constructs a new selection window with just an identifier.
        /// </summary>
        /// <param name="identifier">The text identifier of the window.</param>
        /// <param name="lines">The list of lines in the window.</param>
        public MessageScriptSelectionWindow( string identifier, List<MessageScriptText> lines )
        {
            Identifier = identifier;
            Lines = lines;
        }

        /// <summary>
        /// Constructs a new selection window with just an identifier.
        /// </summary>
        /// <param name="identifier">The text identifier of the window.</param>
        /// <param name="lines">The list of lines in the window.</param>
        public MessageScriptSelectionWindow( string identifier, params MessageScriptText[] lines )
        {
            Identifier = identifier;
            Lines = lines.ToList();
        }

        /// <summary>
        /// Gets the window type.
        /// </summary>
        MessageScriptWindowType IMessageScriptWindow.Type => MessageScriptWindowType.Selection;
    }
}