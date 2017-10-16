namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptAssignmentOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 15;

        public FlowScriptAssignmentOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"{Left} = ({Right})";
        }
    }
}
