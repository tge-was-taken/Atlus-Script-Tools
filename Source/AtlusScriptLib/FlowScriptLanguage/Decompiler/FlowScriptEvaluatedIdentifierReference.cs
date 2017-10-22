using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptEvaluatedIdentifierReference
    {
        public FlowScriptIdentifier Identifier { get; }

        public int InstructionIndex { get; }

        internal FlowScriptEvaluatedIdentifierReference( FlowScriptIdentifier identifier, int instructionIndex )
        {
            Identifier = identifier;
            InstructionIndex = instructionIndex;
        }
    }
}