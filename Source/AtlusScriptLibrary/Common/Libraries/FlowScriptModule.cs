using System;
using System.Collections.Generic;
using System.Linq;
using AtlusScriptLibrary.Common.Libraries.Serialization;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler;
using Newtonsoft.Json;

namespace AtlusScriptLibrary.Common.Libraries
{
    public class FlowScriptModule : ICloneable
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

        public object Clone()
        {
            var clone = new FlowScriptModule();
            clone.Name = Name;
            clone.ShortName = ShortName;
            clone.Description = Description;
            clone.Constants = Constants.Clone()?.ToList();
            clone.Enums = Enums.Clone()?.ToList();
            clone.Functions = Functions.Clone()?.ToList();
            return clone;
        }
    }
}