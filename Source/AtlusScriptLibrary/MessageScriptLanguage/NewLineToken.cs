using System;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Represents a single newline token.
/// </summary>
public class NewLineToken : Token, IEquatable<NewLineToken>
{
    /// <summary>
    /// The constant value of a newline token.
    /// </summary>
    public const byte ASCIIValue = 0x0A;

    /// <summary>
    /// Gets the type of this token.
    /// </summary>
    public override TokenKind Kind => TokenKind.NewLine;

    /// <summary>
    /// Converts this token to its string reprentation.
    /// </summary>
    /// <returns></returns>
    public override string ToString()
    {
        return "<new line>";
    }

    public bool Equals(NewLineToken other) => other is not null;
    public override bool Equals(object obj) => obj is NewLineToken && Equals(obj as NewLineToken);

    public override bool Equals(Token other) => other is not null && other.Kind == TokenKind.NewLine;

    public override int GetHashCode() => HashCode.Combine(Kind, ASCIIValue);
}
