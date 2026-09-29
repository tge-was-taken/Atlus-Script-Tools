using System;
using System.Collections;
using System.Collections.Generic;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Represents a named dialogue message speaker.
/// </summary>
public sealed class NamedSpeaker : Speaker, IEnumerable<Token>, IEquatable<NamedSpeaker>
{
    /// <summary>
    /// Gets the name of the speaker.
    /// </summary>
    public TokenText Name { get; }

    /// <summary>
    /// Constructs a new speaker.
    /// </summary>
    /// <param name="name">The name of the speaker.</param>
    public NamedSpeaker(TokenText name)
    {
        Name = name;
    }

    public NamedSpeaker(string name)
    {
        Name = new TokenTextBuilder()
            .AddString(name)
            .Build();
    }

    /// <summary>
    /// Converts this speaker to its string representation.
    /// </summary>
    /// <returns></returns>
    public override string ToString()
    {
        string str = string.Empty;

        if (Name is not null && Name.Tokens.Count > 0)
        {
            foreach (var token in Name.Tokens)
                str += token + " ";
        }

        return str;
    }

    public IEnumerator<Token> GetEnumerator()
    {
        return ((IEnumerable<Token>)Name).GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return ((IEnumerable<Token>)Name).GetEnumerator();
    }

    public bool Equals(NamedSpeaker other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null) return false;
        return Name == other.Name;
    }

    public override bool Equals(object obj) => obj is NamedSpeaker && Equals(obj as NamedSpeaker);

    public override int GetHashCode() => HashCode.Combine(Kind, Name);

    public override bool Equals(Speaker other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null || other.Kind != SpeakerKind.Named) return false;
        return Name == ((NamedSpeaker)other).Name;
    }

    /// <summary>
    /// Gets the speaker type.
    /// </summary>
    public override SpeakerKind Kind => SpeakerKind.Named;
}