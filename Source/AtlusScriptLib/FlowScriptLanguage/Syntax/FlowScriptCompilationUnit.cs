using System.Collections.Generic;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptCompilationUnit : FlowScriptSyntaxNode
    {
        public List<FlowScriptImport> Imports { get; set; }

        public List<FlowScriptStatement> Statements { get; set; }

        public FlowScriptCompilationUnit()
        {
            Imports = new List<FlowScriptImport>();
            Statements = new List<FlowScriptStatement>();
        }

        public FlowScriptCompilationUnit( List<FlowScriptImport> imports, List<FlowScriptStatement> statements )
        {
            Imports = imports;
            Statements = statements;
        }
    }
}
