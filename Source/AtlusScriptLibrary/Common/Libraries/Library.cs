using AtlusScriptLibrary.Common.Libraries.Serialization;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries;

public class Library : ICloneable
{
    public string Name { get; set; }

    public string ShortName { get; set; }

    [JsonPropertyName("FlowScriptModulesPath")]
    [JsonConverter(typeof(ExternalJsonPathConverter))]
    public List<FlowScriptModule> FlowScriptModules { get; set; }

    [JsonPropertyName("MessageScriptLibraryPath")]
    [JsonConverter(typeof(ExternalJsonPathConverter))]
    public List<MessageScriptLibrary> MessageScriptLibraries { get; set; }

    public object Clone()
    {
        var clone = new Library();
        clone.Name = Name;
        clone.ShortName = ShortName;
        clone.FlowScriptModules = FlowScriptModules.Clone()?.ToList();
        clone.MessageScriptLibraries = MessageScriptLibraries.Clone()?.ToList();
        return clone;
    }
}