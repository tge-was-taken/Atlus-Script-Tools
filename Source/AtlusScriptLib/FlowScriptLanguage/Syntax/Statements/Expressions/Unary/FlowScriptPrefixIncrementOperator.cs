namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptPrefixIncrementOperator : FlowScriptPrefixOperator
    {
        public override string ToString()
        {
            return $"++({Operand})";
        }
    }
}
