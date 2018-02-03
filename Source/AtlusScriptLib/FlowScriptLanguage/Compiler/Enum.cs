using System.Collections.Generic;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler
{
    internal class Enum
    {
        public EnumDeclaration Declaration { get; set; }

        public Dictionary<string, Expression> Members { get; set; }
    }
}