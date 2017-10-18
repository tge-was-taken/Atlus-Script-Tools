namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptPostfixOperator : FlowScriptUnaryExpression, IFlowScriptOperator
    {
        public int Precedence => 2;

        public FlowScriptPostfixOperator() : base( FlowScriptValueType.Unresolved )
        {
        }
    }

    public class FlowScriptPostfixDecrementOperator : FlowScriptPostfixOperator
    {
        public override string ToString()
        {
            return $"({Operand})--";
        }
    }
}
