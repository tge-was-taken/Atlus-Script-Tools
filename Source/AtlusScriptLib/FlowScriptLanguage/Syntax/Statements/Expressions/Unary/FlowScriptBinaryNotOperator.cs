namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptBitwiseNotOperator : FlowScriptUnaryExpression, IFlowScriptOperator
    {
        public int Precedence => 3;

        public FlowScriptBitwiseNotOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"~({Operand})";
        }
    }
}
