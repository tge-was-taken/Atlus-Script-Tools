namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptLiteral<T> : FlowScriptExpression
    {
        public T Value { get; set; }

        protected FlowScriptLiteral( FlowScriptValueType type ) : base( type )
        {
        }

        public override string ToString()
        {
            return Value.ToString();
        }
    }
}
