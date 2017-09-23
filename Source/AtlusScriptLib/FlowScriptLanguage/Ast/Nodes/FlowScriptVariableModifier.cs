namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptVariableModifier : FlowScriptAstNode
    {
        public FlowScriptModifierType ModifierType { get; set; }

        public override string ToString()
        {
            return ModifierType.ToString();
        }
    }

    public enum FlowScriptModifierType
    {
        Local,
        Global
    }
}