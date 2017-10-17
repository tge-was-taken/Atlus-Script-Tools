namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptWhileStatement : FlowScriptStatement
    {
        public FlowScriptExpression Condition { get; set; }

        public FlowScriptCompoundStatement Body { get; set; }

        public FlowScriptWhileStatement()
        {
        }

        public FlowScriptWhileStatement( FlowScriptExpression condition, FlowScriptCompoundStatement body )
        {
            Condition = condition;
            Body = body;
        }
    }
}
