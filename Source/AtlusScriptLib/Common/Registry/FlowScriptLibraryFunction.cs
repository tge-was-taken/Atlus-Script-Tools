using System.Collections.Generic;
using Newtonsoft.Json;

namespace AtlusScriptLib.Common.Registry
{
    public class FlowScriptLibraryFunction
    {
        [JsonConverter(typeof( HexIntStringJsonConverter ) )]
        public int Index { get; set; }

        public string ReturnType { get; set; }

        public string Name { get; set; }

        public string Description { get; set; }

        public List<FlowScriptLibraryFunctionParameter> Parameters { get; set; }
    }
}