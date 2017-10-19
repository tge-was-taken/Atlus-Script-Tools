namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptFloatLiteral : FlowScriptLiteral<float>
    {
        public FlowScriptFloatLiteral() : base( FlowScriptValueType.Float )
        {
        }

        public FlowScriptFloatLiteral( float value ) : base( FlowScriptValueType.Float, value )
        {
        }
    }
}
