using System.Collections.Generic;
using AtlusScriptLib.Common.Registry.Serialization;
using Newtonsoft.Json;

namespace AtlusScriptLib.Common.Registry
{
    public class FlowScriptModuleFunction
    {
        [JsonConverter(typeof( HexIntStringJsonConverter ) )]
        public int Index { get; set; }

        public string ReturnType { get; set; }

        public string Name { get; set; }

        public string Description { get; set; }

        public List<FlowScriptModuleParameter> Parameters { get; set; }
    }
}