using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler;

internal class FunctionInfo
{
    public FunctionDeclaration Declaration { get; set; }

    public short Index { get; set; }
}