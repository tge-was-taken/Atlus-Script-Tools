using System.Collections.Generic;
using AtlusScriptLib.Common.Registry.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AtlusScriptLib.Common.Registry
{
    public class LibraryRegistry
    {
        public string Name { get; set; }

        public string ShortName { get; set; }

        [JsonProperty( "FlowScriptLibraryRegistryPath")]
        [JsonConverter( typeof( ExternalJsonPathConverter) )]
        public List<FlowScriptLibrary> FlowScriptLibraries { get; set; }

        [JsonProperty( "MessageScriptLibraryPath" )]
        [JsonConverter( typeof(ExternalJsonPathConverter) ) ]
        public List<MessageScriptLibrary> MessageScriptLibraries { get; set; }
    }
}