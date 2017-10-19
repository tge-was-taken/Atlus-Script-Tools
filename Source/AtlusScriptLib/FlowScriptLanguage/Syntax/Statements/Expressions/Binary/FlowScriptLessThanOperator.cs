namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptLessThanOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 8;

        public FlowScriptLessThanOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public FlowScriptLessThanOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( FlowScriptValueType.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) < ({Right})";
        }
    }
}
