namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptDivisionAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public FlowScriptDivisionAssignmentOperator()
        {

        }

        public FlowScriptDivisionAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} *= ({Right})";
        }
    }
}
