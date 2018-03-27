namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public abstract class Literal<T> : Expression
    {
        public T Value { get; set; }

        protected Literal( ValueKind kind ) : base( kind )
        {
        }

        protected Literal( ValueKind kind, T value ) : base( kind )
        {
            Value = value;
        }

        public override string ToString()
        {
            return Value.ToString();
        }
    }
}
