namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class ForStatement : Statement
    {
        public Statement Initializer { get; set; }

        public Expression Condition { get; set; }

        public Expression AfterLoop { get; set; }

        public CompoundStatement Body { get; set; }

        public ForStatement()
        {
        }

        public ForStatement( Statement initializer, Expression condition, Expression afterLoop, CompoundStatement body )
        {
            Initializer = initializer;
            Condition = condition;
            AfterLoop = afterLoop;
            Body = body;
        }
    }
}
