namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler;

internal class LabelInfo
{
    public string Name { get; set; }

    public ushort Index { get; set; }

    public short InstructionIndex { get; set; }

    public bool IsResolved { get; set; }

    // Set when the emitter appends the label to the section order itself instead of at resolve time.
    public bool DeferOrder { get; set; }

    // An if statement's own labels sort by where the whole statement ends, else label first.
    public short? SortIndex { get; set; }

    public int SortRank { get; set; }
}