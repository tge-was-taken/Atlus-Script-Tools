using System.Collections.Generic;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptCompilationUnit : FlowScriptSyntaxNode
    {
        public List<FlowScriptImport> Imports { get; set; }

        public List<FlowScriptDeclaration> Declarations { get; set; }

        public FlowScriptCompilationUnit()
        {
            Imports = new List<FlowScriptImport>();
            Declarations = new List<FlowScriptDeclaration>();
        }

        public FlowScriptCompilationUnit( List<FlowScriptImport> imports, List<FlowScriptDeclaration> declarations )
        {
            Imports = imports;
            Declarations = declarations;
        }
    }
}
