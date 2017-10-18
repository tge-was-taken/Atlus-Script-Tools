namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptBitwiseNotOperator : FlowScriptPrefixOperator
    {
        public override string ToString()
        {
            return $"~({Operand})";
        }
    }
}
