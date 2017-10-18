namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptPostfixIncrementOperator : FlowScriptPostfixOperator
    {
        public override string ToString()
        {
            return $"({Operand})++";
        }
    }
}
