namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptVariableModifier : FlowScriptSyntaxNode
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