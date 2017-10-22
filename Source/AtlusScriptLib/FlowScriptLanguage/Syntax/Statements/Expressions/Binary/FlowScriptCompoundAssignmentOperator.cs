namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptCompoundAssignmentOperator : FlowScriptAssignmentOperatorBase
    {
        protected FlowScriptCompoundAssignmentOperator()
        {

        }

        protected FlowScriptCompoundAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }
    }
}
