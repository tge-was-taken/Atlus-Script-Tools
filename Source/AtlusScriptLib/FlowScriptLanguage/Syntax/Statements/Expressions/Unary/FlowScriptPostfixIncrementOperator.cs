namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptPostfixIncrementOperator : FlowScriptPostfixOperator
    {
        public FlowScriptPostfixIncrementOperator()
        {

        }

        public FlowScriptPostfixIncrementOperator( FlowScriptExpression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"({Operand})++";
        }
    }
}
