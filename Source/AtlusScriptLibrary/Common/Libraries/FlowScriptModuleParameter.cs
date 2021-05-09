using AtlusScriptLibrary.Common.Libraries.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace AtlusScriptLibrary.Common.Libraries
{
    public class FlowScriptModuleParameter
    {
        public string Type { get; set; }

        public string Name { get; set; }

        public string Description { get; set; }

        [JsonConverter( typeof( CustomStringEnumConverter ) )]
        public FlowScriptModuleParameterSemantic Semantic { get; set; }
    }

    public enum FlowScriptModuleParameterSemantic
    {
        Normal,
        MsgId,
        SelId,
        BitId,
    }
}