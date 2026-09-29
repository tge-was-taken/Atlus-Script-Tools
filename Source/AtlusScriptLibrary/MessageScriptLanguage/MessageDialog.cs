using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Represents a dialog window in a message script.
/// </summary>
public sealed class MessageDialog : Dialog, IEquatable<MessageDialog>
{
    /// <summary>
    /// Gets or sets the speaker of this dialog window.
    /// </summary>
    public Speaker Speaker { get; set; }

    /// <summary>
    /// Gets the pages contained in this dialog window.
    /// </summary>
    public List<TokenText> Pages { get; }

    public override List<TokenText> Lines => Pages;

    /// <summary>
    /// Constructs a new dialog window with just an identifier.
    /// </summary>
    /// <param name="identifier">The identifier of the window.</param>
    public MessageDialog(string identifier)
    {
        Name = identifier ?? throw new ArgumentNullException(nameof(identifier));
        Speaker = null;
        Pages = new List<TokenText>();
    }

    /// <summary>
    /// Constructs a new dialog window with an identifier and a speaker.
    /// </summary>
    /// <param name="identifier">The identifier of the window.</param>
    /// <param name="speaker">The speaker of the window.</param>
    public MessageDialog(string identifier, Speaker speaker)
    {
        Name = identifier ?? throw new ArgumentNullException(nameof(identifier));
        Speaker = speaker;
        Pages = new List<TokenText>();
    }

    /// <summary>
    /// Constructs a new dialog window with an identifier, a speaker and a list of lines.
    /// </summary>
    /// <param name="identifier">The identifier of the window.</param>
    /// <param name="speaker">The speaker of the window.</param>
    /// <param name="lines">The list of lines of the window.</param>
    public MessageDialog(string identifier, Speaker speaker, List<TokenText> lines)
    {
        Name = identifier ?? throw new ArgumentNullException(nameof(identifier));
        Speaker = speaker;
        Pages = lines ?? throw new ArgumentNullException(nameof(lines));
    }

    /// <summary>
    /// Constructs a new dialog window with an identifier and a list of lines.
    /// </summary>
    /// <param name="identifier">The identifier of the window.</param>
    /// <param name="pages">The list of lines of the window.</param>
    public MessageDialog(string identifier, List<TokenText> pages)
    {
        Name = identifier ?? throw new ArgumentNullException(nameof(identifier));
        Speaker = null;
        Pages = pages;
    }

    /// <summary>
    /// Constructs a new dialog window with an identifier, a speaker and a list of lines.
    /// </summary>
    /// <param name="identifier">The identifier of the window.</param>
    /// <param name="speaker">The speaker of the window.</param>
    /// <param name="lines">The list of lines of the window.</param>
    public MessageDialog(string identifier, Speaker speaker, params TokenText[] lines)
    {
        Name = identifier ?? throw new ArgumentNullException(nameof(identifier));
        Speaker = speaker;
        Pages = lines.ToList();
    }

    /// <summary>
    /// Constructs a new dialog window with an identifier and a list of lines.
    /// </summary>
    /// <param name="identifier">The identifier of the window.</param>
    /// <param name="lines">The list of lines of the window.</param>
    public MessageDialog(string identifier, params TokenText[] lines)
    {
        Name = identifier ?? throw new ArgumentNullException(nameof(identifier));
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
    public override DialogKind Kind => DialogKind.Message;

    public override IEnumerator<TokenText> GetEnumerator()
    {
        return Pages.GetEnumerator();
    }

    public bool Equals(MessageDialog obj)
    {
        if (ReferenceEquals(this, obj)) return true;
        if (obj is null) return false;

        if (Name != obj.Name) return false;
        if (Speaker != obj.Speaker) return false;
        return Pages.SequenceEqual(obj.Pages);
    }

    public override bool Equals(object obj) => obj is MessageDialog && Equals(obj as MessageDialog);

    public override int GetHashCode() => HashCode.Combine(Kind, Name, Speaker, Pages);

    public override bool Equals(Dialog other) => other is MessageDialog && Equals(other as MessageDialog);
}