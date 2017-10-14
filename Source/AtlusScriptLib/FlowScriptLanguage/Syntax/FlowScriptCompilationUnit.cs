using System.Collections.Generic;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptCompilationUnit : FlowScriptSyntaxNode
    {
        public List<FlowScriptImport> Imports { get; set; }

        public List<FlowScriptStatement> Statements { get; set; }
    }
}
