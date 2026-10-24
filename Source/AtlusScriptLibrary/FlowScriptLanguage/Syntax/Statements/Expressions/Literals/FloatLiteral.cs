using System;
using System.Globalization;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax;

public class FloatLiteral : Literal<float>, IEquatable<FloatLiteral>
{
    public FloatLiteral() : base(ValueKind.Float)
    {
    }

    public FloatLiteral(float value) : base(ValueKind.Float, value)
    {
    }

    public override string ToString()
    {
        var text = FormattableString.Invariant($"{Value:0.00#####}");
        if (float.IsNaN(Value) || float.IsInfinity(Value) || ReadsBackExactly(text))
            return text;

        // The fixed format drops precision, so fall back to 9 significant digits, which always reads back.
        var exact = Value.ToString("G9", CultureInfo.InvariantCulture);
        if (exact.IndexOf('.') < 0 && exact.IndexOf('E') < 0 && exact.IndexOf('e') < 0)
            exact += ".0";

        // Framework versions before .NET Core 3.0 drop the sign of a negative zero.
        if (IsNegative(Value) && exact[0] != '-')
            exact = "-" + exact;

        return exact;
    }

    private bool ReadsBackExactly(string text)
    {
        if (!float.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
            return false;

        // Compare the sign separately so a dropped minus on zero counts as a difference.
        return parsed == Value && IsNegative(parsed) == IsNegative(Value);
    }

    private static bool IsNegative(float value) => BitConverter.DoubleToInt64Bits(value) < 0;

    public bool Equals(FloatLiteral other)
    {
        return Value == other?.Value;
    }

    public static implicit operator FloatLiteral(float value) => new FloatLiteral(value);
}
