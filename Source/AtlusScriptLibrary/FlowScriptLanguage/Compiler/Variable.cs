using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler
{
    internal class Variable
    {
        public VariableDeclaration Declaration { get; set; }

        public short Index { get; set; }

        public int Size { get; set; } = 1;

        public short GetArrayElementIndex( int index )
        {
            if ( Declaration.Modifier.Kind != VariableModifierKind.Global )
                return (short)(Index + index);
            else
                return (short)(Index - index);
        }
    }
}