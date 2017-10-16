namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptGreaterThanOrEqualOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 8;

        public FlowScriptGreaterThanOrEqualOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public override string ToString()
        {
            return $"({Left}) >= ({Right})";
        }
    }
}
