using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
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