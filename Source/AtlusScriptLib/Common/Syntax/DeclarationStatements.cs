namespace AtlusScriptLib.Common.Syntax
{
    public abstract class Declaration : Statement
    {
        public Identifier Identifier { get; }

        public Declaration(Identifier identifier)
        {
            Identifier = identifier;
        }

        public override string ToString()
        {
            return Identifier.Name;
        }
    }
}
