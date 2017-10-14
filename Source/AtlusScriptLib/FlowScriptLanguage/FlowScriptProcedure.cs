using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage
{
    public class FlowScriptProcedure
    {
        public string Name { get; set; }

        public List<FlowScriptInstruction> Instructions { get; }

        public List<FlowScriptLabel> Labels { get; }

        public FlowScriptProcedure( string name )
        {
            Name = name;
            Instructions = new List<FlowScriptInstruction>();
            Labels = new List<FlowScriptLabel>();
        }

        public FlowScriptProcedure( string name, List<FlowScriptInstruction> instructions )
        {
            Name = name;
            Instructions = instructions;
            Labels = new List<FlowScriptLabel>();
        }

        public FlowScriptProcedure( string name, List<FlowScriptInstruction> instructions, List<FlowScriptLabel> labels )
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
