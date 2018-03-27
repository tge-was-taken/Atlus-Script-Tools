namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class ReturnStatement : Statement
    {
        public Expression Value { get; set; }

        public ReturnStatement()
        {
            Value = null;
        }

        public ReturnStatement( Expression value )
        {
            Value = value;
        }

        public override string ToString()
        {
            return $"return {Value}";
        }
    }
}
