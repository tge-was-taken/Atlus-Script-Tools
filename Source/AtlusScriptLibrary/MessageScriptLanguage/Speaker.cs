using System;
using System.Collections.Generic;
namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Common interface for dialogue message speakers.
/// </summary>
public abstract class Speaker : IEquatable<Speaker>
{
    /// <summary>
    /// Gets the speaker type.
    /// </summary>
    public abstract SpeakerKind Kind { get; }

    public abstract bool Equals(Speaker other);
    public override bool Equals(object obj) => obj is Speaker && Equals(obj as Speaker);

    public static bool Equals(Speaker x, Speaker y)
    {
        if (ReferenceEquals(x, y)) return true;
        if (x is null) return y is null;
        return x.Equals(y);
    }
    public static bool operator ==(Speaker x, Speaker y) => Equals(x, y);
    public static bool operator !=(Speaker x, Speaker y) => !Equals(x, y);

    public abstract override int GetHashCode();
}