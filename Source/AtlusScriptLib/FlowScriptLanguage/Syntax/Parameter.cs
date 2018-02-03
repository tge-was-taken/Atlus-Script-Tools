namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class Parameter : SyntaxNode
    {
        public TypeIdentifier Type { get; set; }

        public Identifier Identifier { get; set; }

        public Parameter()
        {

        }

        public Parameter( TypeIdentifier type, Identifier identifier )
        {
            Type = type;
            Identifier = identifier;
        }

        public override string ToString()
        {
            return $"{Type} {Identifier}";
        }
    }
}