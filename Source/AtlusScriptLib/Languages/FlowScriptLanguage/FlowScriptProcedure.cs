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

        public FlowScriptProcedure( string name )
        {
            Name = name;
            Instructions = new List<FlowScriptInstruction>();
        }

        public FlowScriptProcedure( string name, List<FlowScriptInstruction> instructions )
        {
            Name = name;
            Instructions = instructions;
        }

        public override string ToString()
        {
            return $"{Name} with {Instructions.Count} instructions";
        }
    }
}
