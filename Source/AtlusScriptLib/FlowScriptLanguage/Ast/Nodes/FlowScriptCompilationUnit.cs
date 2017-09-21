using System.Collections.Generic;

namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptCompilationUnit : FlowScriptAstNode
    {
        public List<FlowScriptImport> Imports { get; set; }

        public List<FlowScriptStatement> Statements { get; set; }
    }
}
