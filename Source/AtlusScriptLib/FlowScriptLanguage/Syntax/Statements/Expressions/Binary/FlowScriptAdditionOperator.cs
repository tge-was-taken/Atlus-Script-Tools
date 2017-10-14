namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptAdditionOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 6;

        public FlowScriptAdditionOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"{Left} + {Right}";
        }
    }
}
