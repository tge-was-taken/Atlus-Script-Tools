namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax;

public interface IExpression : IStatement
{
    ValueKind ExpressionValueKind { get; set; }

    int GetDepth();
}