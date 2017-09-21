using System.Collections.Generic;

namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptProcedureDeclaration : FlowScriptDeclaration
    {
        public FlowScriptTypeIdentifier ReturnType { get; set; }

        public FlowScriptIdentifier Identifier { get; set; }

        public List<FlowScriptParameter> Parameters { get; set; }

        public FlowScriptCompoundStatement Body { get; set; }
    }
}
