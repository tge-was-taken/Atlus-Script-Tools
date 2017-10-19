namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptLogicalOrOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 14;

        public FlowScriptLogicalOrOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public FlowScriptLogicalOrOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( FlowScriptValueType.Bool, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) || ({Right})";
        }
    }
}
