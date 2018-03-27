using System.Collections.Generic;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class CompilationUnit : SyntaxNode
    {
        public List<Import> Imports { get; set; }

        public List<Declaration> Declarations { get; set; }

        public CompilationUnit()
        {
            Imports = new List<Import>();
            Declarations = new List<Declaration>();
        }

        public CompilationUnit( List<Import> imports, List<Declaration> declarations )
        {
            Imports = imports;
            Declarations = declarations;
        }
    }
}
