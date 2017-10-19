namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptNegationOperator : FlowScriptPrefixOperator
    {
        public FlowScriptNegationOperator()
        {

        }

        public FlowScriptNegationOperator( FlowScriptExpression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"-({Operand})";
        }
    }
}
