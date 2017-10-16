namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptPrefixIncrementOperator : FlowScriptUnaryExpression, IFlowScriptOperator
    {
        public int Precedence => 3;

        public FlowScriptPrefixIncrementOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"++({Operand})";
        }
    }
}
