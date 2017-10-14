namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptSubtractionOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 6;

        public FlowScriptSubtractionOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"{Left} - {Right}";
        }
    }
}
