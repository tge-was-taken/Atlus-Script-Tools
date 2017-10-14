namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptTypeIdentifier : FlowScriptIdentifier
    {
        public FlowScriptValueType ValueType { get; set; }

        public FlowScriptTypeIdentifier() : base( FlowScriptValueType.Type )
        {
        }

        public FlowScriptTypeIdentifier( FlowScriptValueType valueType ) : base( FlowScriptValueType.Type )
        {
            ValueType = valueType;
        }
    }
}
