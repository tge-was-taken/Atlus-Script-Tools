namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptMultiplicationOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 5;

        public FlowScriptMultiplicationOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"{Left} * {Right}";
        }
    }
}
