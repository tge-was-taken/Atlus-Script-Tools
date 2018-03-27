namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class VariableModifier : SyntaxNode
    {
        public VariableModifierKind Kind { get; set; }

        public IntLiteral Index { get; set; }

        public VariableModifier()
        {
            Kind = VariableModifierKind.Local;
            Index = null;
        }

        public VariableModifier( VariableModifierKind kind )
        {
            Kind = kind;
            Index = null;
        }

        public VariableModifier( VariableModifierKind kind, IntLiteral index )
        {
            Kind = kind;
            Index = index;
        }

        public override string ToString()
        {
            return Kind.ToString();
        }
    }

    public enum VariableModifierKind
    {
        Local,
        Global,
        Constant,
        AiLocal,
        AiGlobal,
        Bit
    }
}