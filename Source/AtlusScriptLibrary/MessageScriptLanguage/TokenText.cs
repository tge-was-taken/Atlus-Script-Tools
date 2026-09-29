using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Represents a single line of text.
/// </summary>
public class TokenText : IEnumerable<Token>, IEquatable<TokenText>
{
    /// <summary>
    /// Gets the list of tokens contained in this line of text.
    /// </summary>
    public List<Token> Tokens { get; }

    /// <summary>
    /// Construct a new empty message script line.
    /// </summary>
    public TokenText()
    {
        Tokens = new List<Token>();
    }

    /// <summary>
    /// Constructs a new message script line with a list of tokens.
    /// </summary>
    /// <param name="tokens">The list of message script tokens.</param>
    public TokenText(List<Token> tokens)
    {
        Tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));
    }

    /// <summary>
    /// Constructs a new message script line with a list of tokens.
    /// </summary>
    /// <param name="tokens">The list of message script tokens.</param>
    public TokenText(params Token[] tokens)
    {
        Tokens = tokens.ToList();
    }

    /// <summary>
    /// Returns an enumerator that iterates through the tokens in the line.
    /// </summary>
    /// <returns></returns>
    public IEnumerator<Token> GetEnumerator()
    {
        return ((IEnumerable<Token>)Tokens).GetEnumerator();
    }

    /// <summary>
    /// Returns an enumerator that iterates through the tokens in the line.
    /// </summary>
    /// <returns></returns>
    IEnumerator IEnumerable.GetEnumerator()
    {
        return ((IEnumerable<Token>)Tokens).GetEnumerator();
    }

    public bool Equals(TokenText obj)
    {
        if (ReferenceEquals(this, obj)) return true;
        if (obj is null) return false;

        return Tokens.SequenceEqual(obj.Tokens);
    }

    public override bool Equals(object obj)
    {
        if (ReferenceEquals(this, obj)) return true;
        if (obj is null || obj is not TokenText) return false;

        return Tokens.SequenceEqual(((TokenText)obj).Tokens);
    }

    public static bool Equals(TokenText x, TokenText y)
    {
        if (ReferenceEquals(x, y)) return true;
        if (x is null) return y is null;
        return x.Equals(y);
    }

    public override int GetHashCode() => Tokens.GetHashCode();

    public static bool operator ==(TokenText x, TokenText y) => Equals(x, y);
    public static bool operator !=(TokenText x, TokenText y) => !Equals(x, y);
}
