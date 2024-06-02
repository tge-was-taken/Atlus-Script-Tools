using AtlusScriptLibrary.Common.Libraries.Serialization;
using System.Collections.Generic;

namespace AtlusScriptLibrary.Common.Libraries;

public class FlowScriptModuleFunction
{
    [JsonConverter(typeof(HexIntStringJsonConverter))]
    public int Index { get; set; }

    public string ReturnType { get; set; }

    public string Name { get; set; }

    public string Description { get; set; }

    [JsonConverter(typeof(HexIntStringJsonConverter))]
    public int Address { get; set; }

    [JsonConverter(typeof(CustomStringEnumConverter))]
    public FlowScriptModuleFunctionSemantic Semantic { get; set; }

    public List<FlowScriptModuleParameter> Parameters { get; set; }
}

public enum FlowScriptModuleFunctionSemantic
{
    Normal,
    Variadic
}