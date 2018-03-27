using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage
{
    /// <summary>
    /// Represents a dialog window in a message script.
    /// </summary>
    public sealed class MessageDialog : IDialog
    {
        /// <summary>
        /// Gets the text identifier of this dialog window.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the speaker of this dialog window.
        /// </summary>
        public ISpeaker Speaker { get; set; }

        /// <summary>
        /// Gets the pages contained in this dialog window.
        /// </summary>
        public List<TokenText> Pages { get; }

        List< TokenText > IDialog.Lines => Pages;

        /// <summary>
        /// Constructs a new dialog window with just an identifier.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        public MessageDialog( string identifier )
        {
            Name = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = null;
            Pages = new List<TokenText>();
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier and a speaker.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="speaker">The speaker of the window.</param>
        public MessageDialog( string identifier, ISpeaker speaker )
        {
            Name = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = speaker;
            Pages = new List<TokenText>();
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier, a speaker and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="speaker">The speaker of the window.</param>
        /// <param name="lines">The list of lines of the window.</param>
        public MessageDialog( string identifier, ISpeaker speaker, List<TokenText> lines )
        {
            Name = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = speaker;
            Pages = lines ?? throw new ArgumentNullException( nameof( lines ) );
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="pages">The list of lines of the window.</param>
        public MessageDialog( string identifier, List<TokenText> pages )
        {
            Name = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = null;
            Pages = pages;
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier, a speaker and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="speaker">The speaker of the window.</param>
        /// <param name="lines">The list of lines of the window.</param>
        public MessageDialog( string identifier, ISpeaker speaker, params TokenText[] lines )
        {
            Name = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = speaker;
            Pages = lines.ToList();
        }

        /// <summary>
        /// Constructs a new dialog window with an identifier and a list of lines.
        /// </summary>
        /// <param name="identifier">The identifier of the window.</param>
        /// <param name="lines">The list of lines of the window.</param>
        public MessageDialog( string identifier, params TokenText[] lines )
        {
            Name = identifier ?? throw new ArgumentNullException( nameof( identifier ) );
            Speaker = null;
            Pages = lines.ToList();
        }

        /// <summary>
        /// Converts this window to its string representation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"dlg {Name} {Speaker}";
        }

        /// <summary>
        /// Gets the message type of this window.
        /// </summary>
        DialogKind IDialog.Kind => DialogKind.Message;

        public IEnumerator<TokenText> GetEnumerator()
        {
            return Pages.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}