using System;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Represents a code point token. This maps to a glyph on the game's font.
/// </summary>
public class CodePointToken : Token, IEquatable<CodePointToken>
{
    public IReadOnlyList<byte> Bytes { get; }

    /// <summary>
    /// Constructs a new code point token from a high and low surrogate byte.
    /// </summary>
    /// <param name="high">The high surrogate byte.</param>
    /// <param name="low">The low surrogate byte.</param>
    public CodePointToken(byte high, byte low)
    {
        Bytes = new List<byte>() { high, low };
    }

    /// <summary>
    /// Constructs a new code point token from a byte.
    /// </summary>
    public CodePointToken(byte value)
    {
        Bytes = new List<byte>() { value };
    }

    /// <summary>
    /// Constructs a new code point token from a list of bytes.
    /// </summary>
    public CodePointToken(List<byte> bytes)
    {
        Bytes = bytes;
    }

    /// <summary>
    /// Gets the token type of this token.
    /// </summary>
    public override TokenKind Kind => TokenKind.CodePoint;

    /// <summary>
    /// Converts this token to its string representation.
    /// </summary>
    /// <returns></returns>
    public override string ToString()
    {
        return $"[{string.Join(" ", Bytes.Select(x => x.ToString("X2")))}]";
    }

    public bool Equals(CodePointToken other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null) return false;
        return Bytes.SequenceEqual(other.Bytes);
    }

    public override bool Equals(object obj) => obj is CodePointToken && Equals(obj as CodePointToken);

    public override bool Equals(Token other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null || other.Kind != TokenKind.CodePoint) return false;
        return Bytes.SequenceEqual(((CodePointToken)other).Bytes);
    }

    public override int GetHashCode() => HashCode.Combine(Kind, Bytes);
}
