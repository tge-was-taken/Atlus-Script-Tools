using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler
{
    public class EvaluatedIdentifierReference
    {
        public Identifier Identifier { get; }

        public int InstructionIndex { get; }

        internal EvaluatedIdentifierReference( Identifier identifier, int instructionIndex )
        {
            Identifier = identifier;
            InstructionIndex = instructionIndex;
        }
    }
}