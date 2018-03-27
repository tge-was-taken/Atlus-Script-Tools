namespace AtlusScriptLibrary.FlowScriptLanguage.Interpreter
{
    public class StackValue
    {
        public StackValueKind Kind { get; }

        public object Value { get; }

        internal StackValue( StackValueKind kind, object value )
        {
            Kind = kind;
            Value = value;
        }
    }
}