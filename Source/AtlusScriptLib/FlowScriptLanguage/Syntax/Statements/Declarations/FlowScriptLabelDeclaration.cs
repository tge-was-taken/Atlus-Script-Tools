namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptLabelDeclaration : FlowScriptDeclaration
    {
        public FlowScriptLabelDeclaration() : base( FlowScriptDeclarationType.Label )
        {
        }

        public FlowScriptLabelDeclaration( FlowScriptIdentifier identifier ) : base( FlowScriptDeclarationType.Label, identifier )
        {

        }

        public override string ToString()
        {
            return $"{Identifier}:";
        }
    }
}
