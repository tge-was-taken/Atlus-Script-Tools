namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptLogicalAndOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 13;

        public FlowScriptLogicalAndOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public override string ToString()
        {
            return $"{Left} && {Right}";
        }
    }
}
