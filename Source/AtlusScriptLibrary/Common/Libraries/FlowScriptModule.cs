using AtlusScriptLibrary.Common.Libraries.Serialization;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries;

public class FlowScriptModule : ICloneable
{
    public string Name { get; set; }

    public string ShortName { get; set; }

    public string Description { get; set; }

    [JsonPropertyName("ConstantsPath")]
    [JsonConverter(typeof(ExternalJsonPathConverter))]
    public List<FlowScriptModuleConstant> Constants { get; set; }

    [JsonPropertyName("EnumsPath")]
    [JsonConverter(typeof(ExternalJsonPathConverter))]
    public List<FlowScriptModuleEnum> Enums { get; set; }

    [JsonPropertyName("FunctionsPath")]
    [JsonConverter(typeof(ExternalJsonPathConverter))]
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