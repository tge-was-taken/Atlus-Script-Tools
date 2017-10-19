namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptSubtractionOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 6;

        public FlowScriptSubtractionOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public FlowScriptSubtractionOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( FlowScriptValueType.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) - ({Right})";
        }
    }
}
