namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptGreaterThanOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 8;

        public FlowScriptGreaterThanOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public FlowScriptGreaterThanOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( FlowScriptValueType.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) > ({Right})";
        }
    }
}
