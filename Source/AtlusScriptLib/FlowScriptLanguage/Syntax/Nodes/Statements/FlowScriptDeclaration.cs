namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptDeclaration : FlowScriptStatement
    {
        public FlowScriptDeclarationType DeclarationType { get; }

        public FlowScriptIdentifier Identifier { get; set; }

        protected FlowScriptDeclaration( FlowScriptDeclarationType type )
        {
            DeclarationType = type;
        }
    }
}
