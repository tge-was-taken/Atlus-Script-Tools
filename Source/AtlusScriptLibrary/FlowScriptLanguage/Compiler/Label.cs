namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler
{
    internal class Label
    {
        public string Name { get; set; }

        public short Index { get; set; }

        public short InstructionIndex { get; set; }

        public bool IsResolved { get; set; }
    }
}