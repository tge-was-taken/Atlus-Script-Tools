using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage
{
    /// <summary>
    /// Represents a selection window in a message script.
    /// </summary>
    public sealed class SelectionDialog : IDialog
    {
        /// <summary>
        /// Gets the text identifier of this dialog.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets the options contained in this selection dialog.
        /// </summary>
        public List<TokenText> Options { get; }

        List<TokenText> IDialog.Lines => Options;

        /// <summary>
        /// Constructs a new selection dialog with just an identifier.
        /// </summary>
        /// <param name="identifier">The text identifier of the window.</param>
        public SelectionDialog( string identifier )
        {
            Name = identifier;
            Options = new List<TokenText>();
        }

        /// <summary>
        /// Constructs a new selection dialog with just an identifier.
        /// </summary>
        /// <param name="identifier">The text identifier of the dialog.</param>
        /// <param name="pages">The list of lines in the dialog.</param>
        public SelectionDialog( string identifier, List<TokenText> pages )
        {
            Name = identifier;
            Options = pages;
        }

        /// <summary>
        /// Constructs a new selection dialog with just an identifier.
        /// </summary>
        /// <param name="identifier">The text identifier of the dialog.</param>
        /// <param name="pages">The list of lines in the dialog.</param>
        public SelectionDialog( string identifier, params TokenText[] pages )
        {
            Name = identifier;
            Options = pages.ToList();
        }

        /// <summary>
        /// Gets the dialog type.
        /// </summary>
        DialogKind IDialog.Kind => DialogKind.Selection;

        public IEnumerator<TokenText> GetEnumerator()
        {
            return Options.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}