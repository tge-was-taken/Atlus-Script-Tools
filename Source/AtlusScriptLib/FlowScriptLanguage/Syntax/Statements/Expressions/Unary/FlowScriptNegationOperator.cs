namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptNegationOperator : FlowScriptPrefixOperator
    {
        public override string ToString()
        {
            return $"-({Operand})";
        }
    }
}
