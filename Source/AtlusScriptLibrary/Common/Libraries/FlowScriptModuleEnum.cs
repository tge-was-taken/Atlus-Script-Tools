using AtlusScriptLibrary.FlowScriptLanguage.Compiler;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries;

public class FlowScriptModuleEnum : ICloneable
{
    public string Name { get; set; }

    public string Description { get; set; }

    [JsonObjectCreationHandling(JsonObjectCreationHandling.Populate)]
    public List<FlowScriptModuleEnumMember> Members { get; set; } = new();

    public object Clone()
    {
        var clone = new FlowScriptModuleEnum();
        clone.Name = Name;
        clone.Description = Description;
        clone.Members = Members.Clone()?.ToList();
        return clone;
    }
}