using AtlusScriptLibrary.Common.Libraries.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.Collections.Generic;

namespace AtlusScriptLibrary.Common.Libraries
{
    public class MessageScriptLibraryFunction
    {
        public int Index { get; set; }

        public string Name { get; set; }

        public string Description { get; set; }

        [JsonConverter( typeof( CustomStringEnumConverter ) )]
        public MessageScriptLibraryFunctionSemantic Semantic { get; set; }

        public List<MessageScriptLibraryParameter> Parameters { get; set; }
    }

    public enum MessageScriptLibraryFunctionSemantic
    {
        Normal,
        Unused
    }
}