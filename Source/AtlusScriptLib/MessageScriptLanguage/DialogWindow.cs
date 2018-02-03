using System;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents a dialog window in a message script.
    /// </summary>
    public sealed class DialogWindow : IWindow
    {
        /// <summary>
        /// Gets the text identifier of this dialog window.
        /// </summary>
        public string Identifier { get; set; }

        /// <summary>
        /// Gets or sets the speaker of this dialog window.
        /// </summary>
        public Speaker Speaker { get; set; }

        /// <summary>
        /// Gets the lines contained in this message.
        /// </summary>
        public List<TokenText> Lines { get; }

        /// <summary>
        /// Constructs a new dialog window with just an identifier.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        public DialogWindow( string identifier )
        {
            Identifier = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = null;
            Lines = new List<TokenText>();
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier and a speaker.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="speaker">The speaker of the window.</param>
        public DialogWindow( string identifier, Speaker speaker )
        {
            Identifier = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = speaker;
            Lines = new List<TokenText>();
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier, a speaker and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="speaker">The speaker of the window.</param>
        /// <param name="lines">The list of lines of the window.</param>
        public DialogWindow( string identifier, Speaker speaker, List<TokenText> lines )
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
        public DialogWindow( string identifier, List<TokenText> lines )
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
        public DialogWindow( string identifier, Speaker speaker, params TokenText[] lines )
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
        public DialogWindow( string identifier, params TokenText[] lines )
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
        WindowType IWindow.Type => WindowType.Dialogue;
    }
}