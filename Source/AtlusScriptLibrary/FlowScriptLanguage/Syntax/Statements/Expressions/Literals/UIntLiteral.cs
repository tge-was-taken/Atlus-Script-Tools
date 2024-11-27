using System;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax;

public class UIntLiteral : Literal<uint>, IEquatable<UIntLiteral>
{
    public UIntLiteral() : base(ValueKind.Int)
    {
    }

    public UIntLiteral(uint value) : base(ValueKind.UInt, value)
    {
    }

    public bool Equals(UIntLiteral other)
    {
        return Value == other?.Value;
    }

    public static implicit operator UIntLiteral(uint value) => new UIntLiteral(value);
    public static implicit operator UIntLiteral(IntLiteral _intLiteral) => new UIntLiteral((uint)_intLiteral.Value);
}
