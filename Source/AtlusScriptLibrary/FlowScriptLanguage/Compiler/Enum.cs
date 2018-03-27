using System.Collections.Generic;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler
{
    internal class Enum
    {
        public EnumDeclaration Declaration { get; set; }

        public Dictionary<string, Expression> Members { get; set; }
    }
}