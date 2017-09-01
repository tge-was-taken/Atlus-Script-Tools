namespace AtlusScriptLib
{
    /// <summary>
    /// Represents a single named code label in a flow script.
    /// </summary>
    public class FlowScriptLabel
    {
        /// <summary>
        /// Gets the name of the label.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets the instruction index at which this label is located.
        /// </summary>
        public int InstructionIndex { get; }

        /// <summary>
        /// Constructs a new label.
        /// </summary>
        /// <param name="name">The name of the label.</param>
        /// <param name="instructionIndex">The instruction index at which this label is located.</param>
        public FlowScriptLabel(string name, int instructionIndex)
        {
            Name = name;
            InstructionIndex = instructionIndex;
        }
    }
}
