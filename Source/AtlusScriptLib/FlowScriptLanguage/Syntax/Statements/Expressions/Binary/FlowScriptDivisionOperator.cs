namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptDivisionOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 5;

        public FlowScriptDivisionOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"{Left} / {Right}";
        }
    }
}
