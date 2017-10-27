using AtlusScriptLib.FlowScriptLanguage.Decompiler;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptTypeIdentifier : FlowScriptIdentifier
    {
        public FlowScriptValueType ValueType { get; set; }

        public FlowScriptTypeIdentifier() : base( FlowScriptValueType.Type )
        {
        }

        public FlowScriptTypeIdentifier( FlowScriptValueType valueType ) : base( FlowScriptValueType.Type, valueType.ToString() )
        {
            ValueType = valueType;
        }

        public FlowScriptTypeIdentifier( string text ) : base( FlowScriptValueType.Type, text )
        {
            if ( !FlowScriptKeywordConverter.KeywordToValueType.TryGetValue( text, out var valueType ) )
            {
                ValueType = FlowScriptValueType.Int;
            }
            else
            {
                ValueType = valueType;
            }            
        }

        public FlowScriptTypeIdentifier( FlowScriptValueType valueType, string text ) : base( FlowScriptValueType.Type, text )
        {
            ValueType = valueType;
        }
    }
}
