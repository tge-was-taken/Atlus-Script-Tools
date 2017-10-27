using System.Collections.Generic;

namespace AtlusScriptLib.Common.Registry
{
    public class FlowScriptLibraryEnum
    {
        public string Name { get; set; }

        public string Description { get; set; }

        public List<FlowScriptLibraryEnumMember> Members { get; set; }
    }
}