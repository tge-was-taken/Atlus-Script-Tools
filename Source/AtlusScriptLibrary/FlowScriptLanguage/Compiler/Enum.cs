using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using System.Collections.Generic;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler;

internal class Enum
{
    public EnumDeclaration Declaration { get; set; }

    public Dictionary<string, Expression> Members { get; set; }
}