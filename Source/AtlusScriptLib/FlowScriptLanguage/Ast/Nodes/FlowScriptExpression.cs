namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptExpression : FlowScriptStatement
    {
        public FlowScriptPrimitiveType PrimitiveType { get; }
    }

    public class FlowScriptCastExpression : FlowScriptExpression
    {
    }
}