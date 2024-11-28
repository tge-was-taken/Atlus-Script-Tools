namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler;

internal class LabelInfo
{
    public string Name { get; set; }

    public ushort Index { get; set; }

    public short InstructionIndex { get; set; }

    public bool IsResolved { get; set; }
}