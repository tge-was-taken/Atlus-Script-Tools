namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax;

public class NullExpression : Expression
{
    public NullExpression() : base(ValueKind.Null)
    {
    }

    public override int GetHashCode()
    {
        return 11 * 33 ^ 3;
    }

    public override int GetDepth() => 1;
}