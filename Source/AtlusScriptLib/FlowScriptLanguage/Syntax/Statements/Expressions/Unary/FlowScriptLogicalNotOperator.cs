namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptLogicalNotOperator : FlowScriptUnaryExpression, IFlowScriptOperator
    {
        public int Precedence => 3;

        public FlowScriptLogicalNotOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public override string ToString()
        {
            return $"!({Operand})";
        }
    }
}
