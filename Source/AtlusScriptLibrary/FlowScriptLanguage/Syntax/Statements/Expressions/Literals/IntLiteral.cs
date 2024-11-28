using System;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax;

public class IntLiteral : Literal<int>, IEquatable<IntLiteral>, IIntLiteral
{
    public IntLiteral() : base(ValueKind.Int)
    {
    }

    public IntLiteral(int value) : base(ValueKind.Int, value)
    {
    }

    long IIntLiteral.Value => Value;

    public bool Equals(IntLiteral other)
    {
        return Value == other?.Value;
    }

    public static implicit operator IntLiteral(int value) => new IntLiteral(value);
}
