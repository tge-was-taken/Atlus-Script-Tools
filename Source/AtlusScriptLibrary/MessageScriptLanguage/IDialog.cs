using System.Collections.Generic;

namespace AtlusScriptLibrary.MessageScriptLanguage
{
    /// <summary>
    /// Common interface for message script dialog windows.
    /// </summary>
    public interface IDialog : IEnumerable<TokenText>
    {
        /// <summary>
        /// Gets the dialog type of this dialog.
        /// </summary>
        DialogKind Kind { get; }

        /// <summary>
        /// Gets the name of this dialog.
        /// </summary>
        string Name { get; set; }

        /// <summary>
        /// Gets the list of lines contained in this dialog.
        /// </summary>
        List<TokenText> Lines { get; }
    }
}