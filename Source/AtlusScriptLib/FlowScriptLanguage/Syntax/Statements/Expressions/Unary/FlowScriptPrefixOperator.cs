namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptPrefixOperator : FlowScriptUnaryExpression, IFlowScriptOperator
    {
        public int Precedence => 3;

        public FlowScriptPrefixOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public FlowScriptPrefixOperator( FlowScriptExpression operand ) : base( FlowScriptValueType.Unresolved, operand )
        {

        }

        public FlowScriptPrefixOperator( FlowScriptValueType type, FlowScriptExpression operand ) : base( type, operand )
        {
        }
    }
}
