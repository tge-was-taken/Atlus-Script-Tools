namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptStringLiteral : FlowScriptLiteral<string>
    {
        public FlowScriptStringLiteral() : base( FlowScriptValueType.String )
        {
        }

        public FlowScriptStringLiteral( string value ) : base( FlowScriptValueType.String, value )
        {
        }

        public override string ToString()
        {
            return $"\"{Value}\"";
        }
    }
}
