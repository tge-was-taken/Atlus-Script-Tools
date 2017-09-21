namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptVariableModifier : FlowScriptAstNode
    {
        public FlowScriptModifierType ModifierType { get; }
    }

    public enum FlowScriptModifierType
    {
        Local,
        Global
    }
}