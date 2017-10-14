namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptReturnStatement : FlowScriptStatement
    {
        public FlowScriptExpression Value { get; set; }

        public FlowScriptReturnStatement()
        {
            Value = null;
        }

        public FlowScriptReturnStatement( FlowScriptExpression value )
        {
            Value = value;
        }

        public override string ToString()
        {
            return $"return {Value};";
        }
    }
}
