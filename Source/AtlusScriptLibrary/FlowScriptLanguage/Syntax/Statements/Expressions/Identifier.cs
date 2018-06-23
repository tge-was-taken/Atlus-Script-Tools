namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class Identifier : Expression
    {
        public string Text { get; set; }

        public Identifier() : base( ValueKind.Unresolved )
        {
        }

        public Identifier( ValueKind kind ) : base( kind )
        {
        }

        public Identifier( string text ) : base( ValueKind.Unresolved )
        {
            Text = text;
        }

        public Identifier( ValueKind kind, string text ) : base( kind )
        {
            Text = text;
        }

        public override string ToString()
        {
            return Text;
        }

        public override int GetHashCode()
        {
            return Text.GetHashCode();
        }
    }
}
