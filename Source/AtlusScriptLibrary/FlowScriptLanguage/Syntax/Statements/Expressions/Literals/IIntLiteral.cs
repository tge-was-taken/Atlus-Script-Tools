namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax;

public interface IIntLiteral : IExpression
{
    long Value { get; }
}
