using System;
using System.Collections.Generic;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Represents a message script value token.
/// </summary>
public class StringToken : Token, IEquatable<StringToken>
{
    /// <summary>
    /// Gets the value contained by this token. This can be a single word or a whole sentence.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Constructs a new message script value token with a value value.
    /// </summary>
    /// <param name="value">The value value of the value token/</param>
    public StringToken(string value)
    {
        Value = value;
    }

    /// <summary>
    /// Converts this token to its string representation.
    /// </summary>
    /// <returns></returns>
    public override string ToString()
    {
        return Value;
    }

    /// <summary>
    /// Gets the token type.
    /// </summary>
    public override TokenKind Kind => TokenKind.String;

    public bool Equals(StringToken other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null) return false;
        return Value == other.Value;
    }

    public override bool Equals(object obj) => obj is StringToken && Equals(obj as StringToken);

    public override bool Equals(Token other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null || other.Kind != TokenKind.String) return false;
        return Value == ((StringToken)other).Value;
    }

    public override int GetHashCode() => HashCode.Combine(Kind, Value);
}
