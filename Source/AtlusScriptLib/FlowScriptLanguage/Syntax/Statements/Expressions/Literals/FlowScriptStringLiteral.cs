namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptStringLiteral : FlowScriptLiteral<string>
    {
        public FlowScriptStringLiteral() : base( FlowScriptValueType.String )
        {
        }

        public override string ToString()
        {
            return $"\"{Value}\"";
        }
    }
}
