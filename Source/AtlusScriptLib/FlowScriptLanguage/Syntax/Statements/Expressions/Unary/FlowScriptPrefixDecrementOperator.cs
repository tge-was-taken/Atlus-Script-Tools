namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptPrefixDecrementOperator : FlowScriptUnaryExpression, IFlowScriptOperator
    {
        public int Precedence => 3;

        public FlowScriptPrefixDecrementOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"--({Operand})";
        }
    }
}
