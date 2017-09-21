namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptCompoundStatement : FlowScriptStatement
    {
        public FlowScriptList<FlowScriptStatement> Statements { get; }
    }
}