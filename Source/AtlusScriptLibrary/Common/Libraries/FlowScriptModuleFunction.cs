using AtlusScriptLibrary.Common.Libraries.Serialization;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries;

public class FlowScriptModuleFunction : ICloneable
{
    [JsonConverter(typeof(HexIntStringJsonConverter))]
    public int Index { get; set; }

    public string ReturnType { get; set; }

    public string Name { get; set; }

        public List<string> Aliases { get; set; }

        public string Description { get; set; }

    [JsonConverter(typeof(HexIntStringJsonConverter))]
    public int Address { get; set; }

    [JsonConverter(typeof(CustomStringEnumConverter))]
    public FlowScriptModuleFunctionSemantic Semantic { get; set; }

    public List<FlowScriptModuleParameter> Parameters { get; set; }

    public object Clone()
    {
        var clone = new FlowScriptModuleFunction();
        clone.Index = Index;
        clone.ReturnType = ReturnType;
        clone.Name = Name;
        clone.Description = Description;
        clone.Address = Address;
        clone.Semantic = Semantic;
        clone.Parameters = Parameters.Clone()?.ToList();
        clone.Aliases = Aliases.Clone()?.ToList();
        return clone;
    }
}

public enum FlowScriptModuleFunctionSemantic
{
    Normal,
    Variadic
}