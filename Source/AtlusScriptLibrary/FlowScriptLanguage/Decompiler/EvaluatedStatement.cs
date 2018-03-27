using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler
{
    public class EvaluatedStatement
    {
        public Statement Statement { get; }

        public int InstructionIndex { get; }

        public Label ReferencedLabel { get; }

        internal EvaluatedStatement( Statement statement, int instructionIndex, Label referencedLabel )
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