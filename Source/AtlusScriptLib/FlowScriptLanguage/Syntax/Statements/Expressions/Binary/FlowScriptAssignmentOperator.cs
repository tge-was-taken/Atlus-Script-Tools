namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{

    public class FlowScriptAssignmentOperator : FlowScriptAssignmentOperatorBase
    {
        public FlowScriptAssignmentOperator()
        {
        }

        public FlowScriptAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} = ({Right})";
        }
    }
}
