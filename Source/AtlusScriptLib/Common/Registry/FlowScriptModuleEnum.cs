using System.Collections.Generic;

namespace AtlusScriptLib.Common.Registry
{
    public class FlowScriptModuleEnum
    {
        public string Name { get; set; }

        public string Description { get; set; }

        public List<FlowScriptModuleEnumMember> Members { get; set; }
    }
}