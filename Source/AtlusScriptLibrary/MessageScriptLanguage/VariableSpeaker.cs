using System;

namespace AtlusScriptLibrary.MessageScriptLanguage;

public sealed class VariableSpeaker : Speaker, IEquatable<VariableSpeaker>
{
    /// <summary>
    /// Gets the index of the speaker name variable.
    /// </summary>
    public int Index { get; }

    /// <summary>
    /// Constructs a new variable speaker.
    /// </summary>
    /// <param name="index">The index of the speaker name variable.</param>
    public VariableSpeaker(int index)
    {
        Index = index;
    }

    /// <summary>
    /// Converts this speaker to its string representation.
    /// </summary>
    /// <returns></returns>
    public override string ToString()
    {
        return $"<variable name {Index}>";
    }

    public bool Equals(VariableSpeaker other) => other is not null && Index == other.Index;

    public override bool Equals(object obj) => obj is VariableSpeaker && Equals(obj as VariableSpeaker);

    public override int GetHashCode() => HashCode.Combine(Kind, Index);

    public override bool Equals(Speaker other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null || other.Kind != SpeakerKind.Named) return false;
        return Index == ((VariableSpeaker)other).Index;
    }

    /// <summary>
    /// Gets the speaker type.
    /// </summary>
    public override SpeakerKind Kind => SpeakerKind.Variable;
}