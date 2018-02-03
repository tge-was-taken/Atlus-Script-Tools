using System.Collections.Generic;
using AtlusScriptLib.Common.Registry.Serialization;
using Newtonsoft.Json;

namespace AtlusScriptLib.Common.Registry
{
    public class Library
    {
        public string Name { get; set; }

        public string ShortName { get; set; }

        [JsonProperty( "FlowScriptLibraryPath")]
        [JsonConverter( typeof( ExternalJsonPathConverter) )]
        public List<FlowScriptModule> FlowScriptModules { get; set; }

        [JsonProperty( "MessageScriptLibraryPath" )]
        [JsonConverter( typeof(ExternalJsonPathConverter) ) ]
        public List<MessageScriptLibrary> MessageScriptLibraries { get; set; }
    }
}