namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class WhileStatement : Statement
    {
        public Expression Condition { get; set; }

        public CompoundStatement Body { get; set; }

        public WhileStatement()
        {
        }

        public WhileStatement( Expression condition, CompoundStatement body )
        {
            Condition = condition;
            Body = body;
        }
    }
}
