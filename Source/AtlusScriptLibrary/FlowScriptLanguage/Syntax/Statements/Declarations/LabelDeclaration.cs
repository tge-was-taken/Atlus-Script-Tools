namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class LabelDeclaration : Declaration
    {
        public LabelDeclaration() : base( DeclarationType.Label )
        {
        }

        public LabelDeclaration( Identifier identifier ) : base( DeclarationType.Label, identifier )
        {

        }

        public override string ToString()
        {
            return $"{Identifier}:";
        }
    }
}
