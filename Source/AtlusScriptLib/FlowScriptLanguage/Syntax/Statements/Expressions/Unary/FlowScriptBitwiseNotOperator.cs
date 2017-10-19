namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptBitwiseNotOperator : FlowScriptPrefixOperator
    {
        public FlowScriptBitwiseNotOperator()
        {

        }

        public FlowScriptBitwiseNotOperator( FlowScriptExpression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"~({Operand})";
        }
    }
}
