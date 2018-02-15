namespace AtlusScriptLib.FlowScriptLanguage.Interpreter
{
    public enum StackValueKind
    {
        Int,
        Float,
        GlobalIntVariable,
        GlobalFloatVariable,
        String,
        LocalIntVariable,
        LocalFloatVariable,
        ReturnIndex,
    }
}