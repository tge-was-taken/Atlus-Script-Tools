namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptLiteral<T> : FlowScriptExpression
    {
        public T Value { get; set; }

        protected FlowScriptLiteral( FlowScriptValueType type ) : base( type )
        {
        }

        protected FlowScriptLiteral( FlowScriptValueType type, T value ) : base( type )
        {
            Value = value;
        }

        public override string ToString()
        {
            return Value.ToString();
        }
    }
}
