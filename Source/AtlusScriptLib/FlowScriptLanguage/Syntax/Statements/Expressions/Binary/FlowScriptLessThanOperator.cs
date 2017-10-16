namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptLessThanOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 8;

        public FlowScriptLessThanOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public override string ToString()
        {
            return $"({Left}) < ({Right})";
        }
    }
}
