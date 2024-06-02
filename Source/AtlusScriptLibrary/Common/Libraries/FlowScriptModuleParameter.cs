using AtlusScriptLibrary.Common.Libraries.Serialization;
using System;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries;

public class FlowScriptModuleParameter : ICloneable
{
    public string Type { get; set; }

    public string Name { get; set; }

    public string Description { get; set; }

    [JsonConverter(typeof(CustomStringEnumConverter))]
    public FlowScriptModuleParameterSemantic Semantic { get; set; }

    public string DefaultValue { get; set; }

    public object Clone()
    {
        var clone = new FlowScriptModuleParameter();
        clone.Type = Type;
        clone.Name = Name;
        clone.Description = Description;
        clone.Semantic = Semantic;
        clone.DefaultValue = DefaultValue;
        return clone;
    }
}

public enum FlowScriptModuleParameterSemantic
{
    Normal,
    MsgId,
    SelId,
    BitId,
}