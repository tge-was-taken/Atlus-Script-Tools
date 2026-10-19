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

    public bool UsePOPREG { get; set; }

    /// <summary>
    /// Format version of the MessageScript embedded in this game's FlowScripts. V1 and the
    /// DDS variant are indistinguishable from the binary alone, so the library states it.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter<MessageScriptLanguage.FormatVersion>))]
    public MessageScriptLanguage.FormatVersion MessageScriptFormatVersion { get; set; }
        = MessageScriptLanguage.FormatVersion.Detect;

    [JsonPropertyName("FlowScriptModulesPath")]
    [JsonConverter(typeof(ExternalJsonPathConverter<FlowScriptModule>))]
    public List<FlowScriptModule> FlowScriptModules { get; set; }

    [JsonPropertyName("MessageScriptLibraryPath")]
    [JsonConverter(typeof(ExternalJsonPathConverter<MessageScriptLibrary>))]
    public List<MessageScriptLibrary> MessageScriptLibraries { get; set; }

    public object Clone()
    {
        var clone = new Library();
        clone.Name = Name;
        clone.ShortName = ShortName;
        clone.UsePOPREG = UsePOPREG;
        clone.MessageScriptFormatVersion = MessageScriptFormatVersion;
        clone.FlowScriptModules = FlowScriptModules.Clone()?.ToList();
        clone.MessageScriptLibraries = MessageScriptLibraries.Clone()?.ToList();
        return clone;
    }
}