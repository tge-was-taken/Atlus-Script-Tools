namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptPostfixOperator : FlowScriptUnaryExpression, IFlowScriptOperator
    {
        public int Precedence => 2;

        protected FlowScriptPostfixOperator() : base( FlowScriptValueType.Unresolved )
        {
        }

        protected FlowScriptPostfixOperator( FlowScriptExpression operand ) : base( FlowScriptValueType.Unresolved, operand )
        {

        }
    }

    public class FlowScriptPostfixDecrementOperator : FlowScriptPostfixOperator
    {
        public FlowScriptPostfixDecrementOperator()
        {

        }

        public FlowScriptPostfixDecrementOperator( FlowScriptExpression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"({Operand})--";
        }
    }
}
