namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptPrefixIncrementOperator : FlowScriptPrefixOperator
    {
        public FlowScriptPrefixIncrementOperator()
        {

        }

        public FlowScriptPrefixIncrementOperator( FlowScriptExpression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"++({Operand})";
        }
    }
}
