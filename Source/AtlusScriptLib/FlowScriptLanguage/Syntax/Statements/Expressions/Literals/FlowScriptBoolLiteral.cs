namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptBoolLiteral : FlowScriptLiteral<bool>
    {
        public FlowScriptBoolLiteral( ) : base( FlowScriptValueType.Bool )
        {
        }

        public FlowScriptBoolLiteral( bool value ) : base( FlowScriptValueType.Bool, value )
        {
        }
    }
}
