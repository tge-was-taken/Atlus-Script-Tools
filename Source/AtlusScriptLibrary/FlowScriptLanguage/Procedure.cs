using System.Collections.Generic;

namespace AtlusScriptLibrary.FlowScriptLanguage
{
    public class Procedure
    {
        public string Name { get; set; }

        public List<Instruction> Instructions { get; }

        public List<Label> Labels { get; }

        public Procedure( string name )
        {
            Name = name;
            Instructions = new List<Instruction>();
            Labels = new List<Label>();
        }

        public Procedure( string name, List<Instruction> instructions )
        {
            Name = name;
            Instructions = instructions;
            Labels = new List<Label>();
        }

        public Procedure( string name, List<Instruction> instructions, List<Label> labels )
        {
            Name = name;
            Instructions = instructions;
            Labels = labels;
        }

        public override string ToString()
        {
            return $"{Name} with {Instructions.Count} instructions";
        }
    }
}
