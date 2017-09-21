using System.Collections.Generic;

namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptVariableDeclaration : FlowScriptDeclaration
    {
        public List<FlowScriptVariableModifier> Modifiers { get; }

        public FlowScriptTypeIdentifier TypeIdentifier { get; }

        public FlowScriptIdentifier Identifier { get; }

        public FlowScriptExpression Initializer { get; }
    }
}
