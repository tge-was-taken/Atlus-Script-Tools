using System.Collections.Generic;
using AtlusScriptLibrary.Common.Libraries.Serialization;
using Newtonsoft.Json;

namespace AtlusScriptLibrary.Common.Libraries
{
    public class Library
    {
        public string Name { get; set; }

        public string ShortName { get; set; }

        [JsonProperty( "FlowScriptModulesPath")]
        [JsonConverter( typeof( ExternalJsonPathConverter) )]
        public List<FlowScriptModule> FlowScriptModules { get; set; }

        [JsonProperty( "MessageScriptLibraryPath" )]
        [JsonConverter( typeof(ExternalJsonPathConverter) ) ]
        public List<MessageScriptLibrary> MessageScriptLibraries { get; set; }
    }
}