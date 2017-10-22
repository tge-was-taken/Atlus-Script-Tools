namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptSubtractionAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public FlowScriptSubtractionAssignmentOperator()
        {

        }

        public FlowScriptSubtractionAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} -= ({Right})";
        }
    }
}
