using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Represents a selection window in a message script.
/// </summary>
public sealed class SelectionDialog : Dialog, IEquatable<SelectionDialog>
{
    /// <summary>
    /// Gets or sets the selection pattern of the dialog.
    /// </summary>
    public SelectionDialogPattern Pattern { get; set; }

    /// <summary>
    /// Gets the options contained in this selection dialog.
    /// </summary>
    public List<TokenText> Options { get; }

    public override List<TokenText> Lines => Options;

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
    public override DialogKind Kind => DialogKind.Selection;

    public override IEnumerator<TokenText> GetEnumerator()
    {
        return Options.GetEnumerator();
    }

    public bool Equals(SelectionDialog obj)
    {
        if (ReferenceEquals(this, obj)) return true;
        if (obj is null) { return false; }

        if (Name != obj.Name) return false;
        if (Pattern != obj.Pattern) return false;
        return Options.SequenceEqual(obj.Options);
    }

    public override bool Equals(object obj)
    {
        if (ReferenceEquals(this, obj)) return true;
        if (obj is null || obj is not SelectionDialog) return false;

        return Equals(obj as SelectionDialog);
    }

    public override int GetHashCode() => HashCode.Combine(Kind, Name, Options, Pattern);

    public override bool Equals(Dialog other) => other is SelectionDialog && Equals(other as SelectionDialog);
}