namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{

    public class FlowScriptPrefixDecrementOperator : FlowScriptPrefixOperator
    {
        public FlowScriptPrefixDecrementOperator()
        {

        }

        public FlowScriptPrefixDecrementOperator( FlowScriptExpression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"--({Operand})";
        }
    }
}
