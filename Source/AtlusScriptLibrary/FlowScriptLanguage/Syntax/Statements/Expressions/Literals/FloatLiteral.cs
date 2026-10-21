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
        if (float.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) &&
            parsed.Equals(Value))
            return text;

        // The fixed format drops precision, so fall back to the shortest text that reads back bit for bit.
        var exact = Value.ToString("R", CultureInfo.InvariantCulture);
        if (exact.IndexOf('.') < 0 && exact.IndexOf('E') < 0 && exact.IndexOf('e') < 0)
            exact += ".0";
        return exact;
    }

    public bool Equals(FloatLiteral other)
    {
        return Value == other?.Value;
    }

    public static implicit operator FloatLiteral(float value) => new FloatLiteral(value);
}
