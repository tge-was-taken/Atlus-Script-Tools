namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptGreaterThanOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 8;

        public FlowScriptGreaterThanOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public override string ToString()
        {
            return $"({Left}) > ({Right})";
        }
    }
}
