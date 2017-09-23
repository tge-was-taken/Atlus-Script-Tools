namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
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
