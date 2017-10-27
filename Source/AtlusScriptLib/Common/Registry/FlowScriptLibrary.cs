using System.Collections.Generic;
using Newtonsoft.Json;

namespace AtlusScriptLib.Common.Registry
{
    public class FlowScriptLibrary
    {
        public string Name { get; set; }

        public string ShortName { get; set; }

        public string Description { get; set; }

        [JsonProperty( "ConstantsPath" )]
        [JsonConverter( typeof( ExternalJsonPathConverter ) )]
        public List<FlowScriptLibraryConstant> Constants { get; set; }

        [JsonProperty( "EnumsPath" )]
        [JsonConverter( typeof( ExternalJsonPathConverter ) )]
        public List<FlowScriptLibraryEnum> Enums { get; set; }

        [JsonProperty( "FunctionsPath" )]
        [JsonConverter( typeof( ExternalJsonPathConverter ) )]
        public List<FlowScriptLibraryFunction> Functions { get; set; }
    }
}