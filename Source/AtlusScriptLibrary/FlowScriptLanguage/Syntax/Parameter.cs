namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class Parameter : SyntaxNode
    {
        public ParameterModifier Modifier { get; set; }

        public TypeIdentifier Type { get; set; }

        public Identifier Identifier { get; set; }

        public virtual bool IsArray => false;

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
            return $"{(Modifier == ParameterModifier.Out ? "out " : "")}{Type} {Identifier}";
        }
    }

    public class ArrayParameter : Parameter
    {
        public IntLiteral Size { get; set; }

        public override bool IsArray => true;

        public ArrayParameter()
        {
            
        }

        public ArrayParameter( ParameterModifier modifier, TypeIdentifier type, Identifier identifier, IntLiteral size ) : base(modifier, type, identifier)
        {
            Size = size;
        }

        public override string ToString()
        {
            return base.ToString() + $"[{Size}]";
        }
    }
}