namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptGreaterThanOrEqualOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 8;

        public FlowScriptGreaterThanOrEqualOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public FlowScriptGreaterThanOrEqualOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( FlowScriptValueType.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) >= ({Right})";
        }
    }
}
