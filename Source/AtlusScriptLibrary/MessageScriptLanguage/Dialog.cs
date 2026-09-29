using System;
using System.Collections;
using System.Collections.Generic;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Common interface for message script dialog windows.
/// </summary>
public abstract class Dialog : IEnumerable<TokenText>, IEquatable<Dialog>
{
    /// <summary>
    /// Gets the dialog type of this dialog.
    /// </summary>
    public abstract DialogKind Kind { get; }

    /// <summary>
    /// Gets the text identifier of this dialog window.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Gets the list of lines contained in this dialog.
    /// </summary>
    public abstract List<TokenText> Lines { get; }

    public abstract bool Equals(Dialog other);
    public override bool Equals(object obj) => obj is Dialog && Equals(obj as Dialog);
    public static bool Equals(Dialog x, Dialog y)
    {
        if (ReferenceEquals(x, y)) return true;
        if (x is null) return y is null;
        return x.Equals(y);
    }

    public abstract IEnumerator<TokenText> GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    public abstract override int GetHashCode();

    public static bool operator ==(Dialog x, Dialog y) => Equals(x, y);
    public static bool operator !=(Dialog x, Dialog y) => !Equals(x, y);
}