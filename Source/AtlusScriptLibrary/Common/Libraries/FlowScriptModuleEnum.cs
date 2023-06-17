using System;
using System.Collections.Generic;
using System.Linq;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler;

namespace AtlusScriptLibrary.Common.Libraries
{
    public class FlowScriptModuleEnum : ICloneable
    {
        public string Name { get; set; }

        public string Description { get; set; }

        public List<FlowScriptModuleEnumMember> Members { get; set; }

        public object Clone()
        {
            var clone = new FlowScriptModuleEnum();
            clone.Name = Name;
            clone.Description = Description;
            clone.Members = Members.Clone()?.ToList();
            return clone;
        }
    }
}