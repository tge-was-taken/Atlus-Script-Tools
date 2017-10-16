namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptLabelDeclaration : FlowScriptDeclaration
    {
        public FlowScriptLabelDeclaration() : base( FlowScriptDeclarationType.Label )
        {
        }

        public override string ToString()
        {
            return $"{Identifier}:";
        }
    }
}
