namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptLessThanOrEqualOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 8;

        public FlowScriptLessThanOrEqualOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public FlowScriptLessThanOrEqualOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( FlowScriptValueType.Bool, left, right )
        {

        }


        public override string ToString()
        {
            return $"({Left}) <= ({Right})";
        }
    }
}
