namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptPrefixOperator : FlowScriptUnaryExpression, IFlowScriptOperator
    {
        public int Precedence => 3;

        public FlowScriptPrefixOperator() : base( FlowScriptValueType.Unresolved )
        {
        }
    }

    public class FlowScriptPrefixDecrementOperator : FlowScriptPrefixOperator
    {
        public override string ToString()
        {
            return $"--({Operand})";
        }
    }
}
