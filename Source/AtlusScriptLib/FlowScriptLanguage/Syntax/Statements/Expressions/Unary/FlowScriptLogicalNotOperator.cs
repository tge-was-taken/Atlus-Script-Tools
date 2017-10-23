namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptLogicalNotOperator : FlowScriptPrefixOperator
    {
        public FlowScriptLogicalNotOperator()
        {

        }

        public FlowScriptLogicalNotOperator( FlowScriptExpression operand ) : base( FlowScriptValueType.Bool, operand )
        {

        }

        public override string ToString()
        {
            return $"!({Operand})";
        }
    }
}
