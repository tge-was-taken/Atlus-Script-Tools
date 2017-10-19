namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptPrefixOperator : FlowScriptUnaryExpression, IFlowScriptOperator
    {
        public int Precedence => 3;

        public FlowScriptPrefixOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public FlowScriptPrefixOperator( FlowScriptExpression operand ) : base( FlowScriptValueType.Unresolved, operand )
        {

        }
    }

    public class FlowScriptPrefixDecrementOperator : FlowScriptPrefixOperator
    {
        public FlowScriptPrefixDecrementOperator()
        {

        }

        public FlowScriptPrefixDecrementOperator( FlowScriptExpression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"--({Operand})";
        }
    }
}
