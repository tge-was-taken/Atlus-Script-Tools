namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptAdditionAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public FlowScriptAdditionAssignmentOperator()
        {

        }

        public FlowScriptAdditionAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} += ({Right})";
        }
    }
}
