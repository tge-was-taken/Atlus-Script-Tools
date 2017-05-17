namespace AtlusScriptLib
{
    public class FlowScriptLabel
    {
        public string Name { get; }

        public int InstructionIndex { get; }

        public FlowScriptLabel(string name, int instructionIndex)
        {
            Name = name;
            InstructionIndex = instructionIndex;
        }
    }
}
