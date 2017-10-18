namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptIntLiteral : FlowScriptLiteral<int>
    {
        public FlowScriptIntLiteral() : base( FlowScriptValueType.Int )
        {
        }

        public FlowScriptIntLiteral( int value ) : base( FlowScriptValueType.Int, value )
        {
        }
    }
}
