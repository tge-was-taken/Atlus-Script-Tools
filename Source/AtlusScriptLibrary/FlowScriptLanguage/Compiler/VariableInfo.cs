using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler;

internal class VariableInfo
{
    public VariableDeclaration Declaration { get; set; }

    public ushort Index { get; set; }

    public int Size { get; set; } = 1;

    public ushort GetArrayElementIndex(int index)
    {
        if (Declaration.Modifier.Kind != VariableModifierKind.Global)
            return (ushort)(Index + index);
        else
            return (ushort)(Index - index);
    }
}