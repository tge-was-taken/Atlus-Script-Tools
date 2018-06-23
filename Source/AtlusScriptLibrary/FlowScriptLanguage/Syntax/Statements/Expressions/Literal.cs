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

        public static implicit operator T(Literal<T> value) => value.Value;

        public override string ToString()
        {
            return Value.ToString();
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }
    }
}
