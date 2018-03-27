using System.Collections.Generic;
using AtlusScriptLibrary.Common.Libraries.Serialization;
using Newtonsoft.Json;

namespace AtlusScriptLibrary.Common.Libraries
{
    public class FlowScriptModule
    {
        public string Name { get; set; }

        public string ShortName { get; set; }

        public string Description { get; set; }

        [JsonProperty( "ConstantsPath" )]
        [JsonConverter( typeof( ExternalJsonPathConverter ) )]
        public List<FlowScriptModuleConstant> Constants { get; set; }

        [JsonProperty( "EnumsPath" )]
        [JsonConverter( typeof( ExternalJsonPathConverter ) )]
        public List<FlowScriptModuleEnum> Enums { get; set; }

        [JsonProperty( "FunctionsPath" )]
        [JsonConverter( typeof( ExternalJsonPathConverter ) )]
        public List<FlowScriptModuleFunction> Functions { get; set; }
    }
}