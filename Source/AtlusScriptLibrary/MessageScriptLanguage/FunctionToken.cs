using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage;

/// <summary>
/// Represents a message script function token.
/// </summary>
public struct FunctionToken : IToken
{
    /// <summary>
    /// Gets the function table index.
    /// </summary>
    public int FunctionTableIndex { get; }

    /// <summary>
    /// Gets the function index within the table.
    /// </summary>
    public int FunctionIndex { get; }

    /// <summary>
    /// Gets the list of arguments.
    /// </summary>
    public List<ushort> Arguments { get; }

    /// <summary>
    /// Prefixes every message function with an 0xFE byte (Persona 3 Reload)
    /// </summary>
    public bool UseIdentifierByte { get; }

    /// <summary>
    /// Constructs a new message script function token with no arguments.
    /// </summary>
    /// <param name="functionTableIndex">The function table index.</param>
    /// <param name="functionIndex">The function index within the table.</param>
    public FunctionToken(int functionTableIndex, int functionIndex, bool useIdentifierByte)
    {
        FunctionTableIndex = functionTableIndex;
        FunctionIndex = functionIndex;
        Arguments = new List<ushort>();
        UseIdentifierByte = useIdentifierByte;
    }

    /// <summary>
    /// Constructs a new message script function token with arguments.
    /// </summary>
    /// <param name="functionTableIndex">The function table index.</param>
    /// <param name="functionIndex">The function index within the table.</param>
    /// <param name="arguments">The function arguments.</param>
    public FunctionToken(int functionTableIndex, int functionIndex, List<ushort> arguments, bool useIdentifierByte)
    {
        FunctionTableIndex = functionTableIndex;
        FunctionIndex = functionIndex;
        Arguments = arguments;
        UseIdentifierByte = useIdentifierByte;
    }

    /// <summary>
    /// Constructs a new message script function token with arguments.
    /// </summary>
    /// <param name="functionTableIndex">The function table index.</param>
    /// <param name="functionIndex">The function index within the table.</param>
    /// <param name="arguments">The function arguments.</param>
    public FunctionToken(int functionTableIndex, int functionIndex, bool useIdentifierByte, params ushort[] arguments)
    {
        FunctionTableIndex = functionTableIndex;
        FunctionIndex = functionIndex;
        Arguments = arguments.ToList();
        UseIdentifierByte = useIdentifierByte;
    }

    /// <summary>
    /// Converts this message script function token to its string representation.
    /// </summary>
    /// <returns></returns>
    public override string ToString()
    {
        string str = $"func_{FunctionTableIndex}_{FunctionIndex}(";
        for (int i = 0; i < Arguments.Count; i++)
        {
            str += Arguments[i];
            if (i + 1 != Arguments.Count)
                str += ",";
        }
        str += ")";

        return str;
    }

    /// <summary>
    /// Gets the token type.
    /// </summary>
    TokenKind IToken.Kind => TokenKind.Function;
}
