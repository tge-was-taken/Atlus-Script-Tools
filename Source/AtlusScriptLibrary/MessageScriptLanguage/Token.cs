using System;
using System.Collections.Generic;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Common interface for message script line tokens.
/// </summary>
public abstract class Token : IEquatable<Token>
{
    /// <summary>
    /// Gets the type of token.
    /// </summary>
    public abstract TokenKind Kind { get; }

    public abstract bool Equals(Token other);
    public static bool Equals(Token x, Token y)
    {
        if (ReferenceEquals(x, y)) return true;
        if (x is null) return y is null;
        return x.Equals(y);
    }
    public override bool Equals(object obj) => obj is Token && Equals(obj as Token);
    public static bool operator ==(Token x, Token y) => Equals(x, y);
    public static bool operator !=(Token x, Token y) => !Equals(x, y);

    public abstract override int GetHashCode();
}