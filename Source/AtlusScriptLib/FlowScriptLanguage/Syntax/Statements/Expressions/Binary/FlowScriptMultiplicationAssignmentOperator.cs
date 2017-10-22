namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptMultiplicationAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public FlowScriptMultiplicationAssignmentOperator()
        {

        }

        public FlowScriptMultiplicationAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} *= ({Right})";
        }
    }
}
