using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using System.Collections.Generic;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler
{
    internal class ProcedureInfo
    {
        public ProcedureDeclaration Declaration { get; set; }

        public Procedure Compiled { get; set; }

        public Procedure OriginalCompiled { get; set; }

        public short Index { get; set; }

        public bool IndexForced { get; set; }
    }
}