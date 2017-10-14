namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptNegationOperator : FlowScriptUnaryExpression, IFlowScriptOperator
    {
        public int Precedence => 3;

        public FlowScriptNegationOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"-{Operand}";
        }
    }
}
