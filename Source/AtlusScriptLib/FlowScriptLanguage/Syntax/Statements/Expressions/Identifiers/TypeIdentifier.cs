using AtlusScriptLib.FlowScriptLanguage.Decompiler;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class TypeIdentifier : Identifier
    {
        public ValueKind ValueKind { get; set; }

        public TypeIdentifier() : base( ValueKind.Type )
        {
        }

        public TypeIdentifier( ValueKind valueKind ) : base( ValueKind.Type, KeywordDictionary.ValueTypeToKeyword[valueKind] )
        {
            ValueKind = valueKind;
        }

        public TypeIdentifier( string text ) : base( ValueKind.Type, text )
        {
            if ( !KeywordDictionary.KeywordToValueType.TryGetValue( text, out var valueType ) )
            {
                ValueKind = ValueKind.Int;
            }
            else
            {
                ValueKind = valueType;
            }            
        }

        public TypeIdentifier( ValueKind valueKind, string text ) : base( ValueKind.Type, text )
        {
            ValueKind = valueKind;
        }
    }
}
