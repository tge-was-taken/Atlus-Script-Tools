using System.Collections.Generic;

namespace AtlusScriptLibrary.Common.Libraries
{
    public class FlowScriptModuleEnum
    {
        public string Name { get; set; }

        public string Description { get; set; }

        public List<FlowScriptModuleEnumMember> Members { get; set; }
    }
}