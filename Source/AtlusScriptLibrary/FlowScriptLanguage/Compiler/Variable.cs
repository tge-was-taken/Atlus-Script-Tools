using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler
{
    internal class Variable
    {
        public VariableDeclaration Declaration { get; set; }

        public short Index { get; set; }
    }
}