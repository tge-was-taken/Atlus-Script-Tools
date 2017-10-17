namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptForStatement : FlowScriptStatement
    {
        public FlowScriptStatement Initializer { get; set; }

        public FlowScriptExpression Condition { get; set; }

        public FlowScriptExpression AfterLoop { get; set; }

        public FlowScriptCompoundStatement Body { get; set; }

        public FlowScriptForStatement()
        {
        }

        public FlowScriptForStatement( FlowScriptStatement initializer, FlowScriptExpression condition, FlowScriptExpression afterLoop, FlowScriptCompoundStatement body )
        {
            Initializer = initializer;
            Condition = condition;
            AfterLoop = afterLoop;
            Body = body;
        }
    }
}
