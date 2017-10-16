namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptLogicalOrOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 14;

        public FlowScriptLogicalOrOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public override string ToString()
        {
            return $"({Left}) || ({Right})";
        }
    }
}
