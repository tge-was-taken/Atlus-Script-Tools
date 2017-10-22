using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptEvaluatedStatement
    {
        public FlowScriptStatement Statement { get; }

        public int InstructionIndex { get; }

        public FlowScriptLabel ReferencedLabel { get; }

        internal FlowScriptEvaluatedStatement( FlowScriptStatement statement, int instructionIndex, FlowScriptLabel referencedLabel )
        {
            Statement = statement;
            InstructionIndex = instructionIndex;
            ReferencedLabel = referencedLabel;
        }

        public override string ToString()
        {
            return $"{Statement} at {InstructionIndex}";
        }
    }
}