namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptAssignmentOperatorBase : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 15;

        protected FlowScriptAssignmentOperatorBase() : base( FlowScriptValueType.Unresolved )
        {
        }

        protected FlowScriptAssignmentOperatorBase( FlowScriptExpression left, FlowScriptExpression right )
            : base( FlowScriptValueType.Unresolved, left, right )
        {

        }
    }
}
