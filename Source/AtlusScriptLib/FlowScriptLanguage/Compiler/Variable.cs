using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler
{
    internal class Variable
    {
        public VariableDeclaration Declaration { get; set; }

        public short Index { get; set; }
    }
}