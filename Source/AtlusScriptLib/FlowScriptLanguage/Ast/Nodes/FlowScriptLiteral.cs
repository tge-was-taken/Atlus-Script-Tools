namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public abstract class FlowScriptLiteral<T> : FlowScriptAstNode
    {
        public T Value { get; }
    }
}
