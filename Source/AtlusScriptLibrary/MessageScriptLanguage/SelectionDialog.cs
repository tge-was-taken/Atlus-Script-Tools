using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage;

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
    /// Gets or sets the selection pattern of the dialog.
    /// </summary>
    public SelectionDialogPattern Pattern { get; set; }

    /// <summary>
    /// Gets the options contained in this selection dialog.
    /// </summary>
    public List<TokenText> Options { get; }

    List<TokenText> IDialog.Lines => Options;

    /// <summary>
    /// Constructs a new selection dialog with just an identifier.
    /// </summary>
    /// <param name="identifier">The text identifier of the window.</param>
    public SelectionDialog(string identifier, SelectionDialogPattern pattern = SelectionDialogPattern.Top)
    {
        Name = identifier;
        Pattern = pattern;
        Options = new List<TokenText>();
    }

    /// <summary>
    /// Constructs a new selection dialog with just an identifier.
    /// </summary>
    /// <param name="identifier">The text identifier of the dialog.</param>
    /// <param name="pages">The list of lines in the dialog.</param>
    public SelectionDialog(string identifier, SelectionDialogPattern pattern, List<TokenText> pages)
    {
        Name = identifier;
        Pattern = pattern;
        Options = pages;
    }

    /// <summary>
    /// Constructs a new selection dialog with just an identifier.
    /// </summary>
    /// <param name="identifier">The text identifier of the dialog.</param>
    /// <param name="pages">The list of lines in the dialog.</param>
    public SelectionDialog(string identifier, SelectionDialogPattern pattern, params TokenText[] pages)
    {
        Name = identifier;
        Pattern = pattern;
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