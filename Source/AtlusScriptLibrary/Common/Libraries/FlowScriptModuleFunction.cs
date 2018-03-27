using System.Collections.Generic;
using AtlusScriptLibrary.Common.Libraries.Serialization;
using Newtonsoft.Json;

namespace AtlusScriptLibrary.Common.Libraries
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