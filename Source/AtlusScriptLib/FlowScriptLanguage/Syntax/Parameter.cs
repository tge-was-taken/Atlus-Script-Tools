namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class Parameter : SyntaxNode
    {
        public ParameterModifier Modifier { get; set; }

        public TypeIdentifier Type { get; set; }

        public Identifier Identifier { get; set; }

        public Parameter()
        {
        }

        public Parameter( ParameterModifier modifier, TypeIdentifier type, Identifier identifier )
        {
            Modifier = modifier;
            Type = type;
            Identifier = identifier;
        }

        public override string ToString()
        {
            return $"{(Modifier == ParameterModifier.Out ? "Out " : "")}{Type} {Identifier}";
        }
    }
}