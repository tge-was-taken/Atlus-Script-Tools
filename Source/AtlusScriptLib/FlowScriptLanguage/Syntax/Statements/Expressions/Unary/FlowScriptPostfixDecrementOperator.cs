namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{

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
