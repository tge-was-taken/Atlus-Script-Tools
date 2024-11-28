using System;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax;

public class UIntLiteral : Literal<uint>, IEquatable<UIntLiteral>, IIntLiteral
{
    public UIntLiteral() : base(ValueKind.UInt)
    {
    }

    public UIntLiteral(uint value) : base(ValueKind.UInt, value)
    {
    }

    long IIntLiteral.Value => Value;

    public bool Equals(UIntLiteral other)
    {
        return Value == other?.Value;
    }

    public static implicit operator UIntLiteral(uint value) => new UIntLiteral(value);
}
