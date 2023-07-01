using AtlusScriptLibrary.Common.Libraries.Serialization;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries;

public class MessageScriptLibraryFunction : ICloneable
{
    public int Index { get; set; }

    public string Name { get; set; }

    public string Description { get; set; }

    [JsonConverter(typeof(CustomStringEnumConverter))]
    public MessageScriptLibraryFunctionSemantic Semantic { get; set; }

    public List<MessageScriptLibraryParameter> Parameters { get; set; }

    public object Clone()
    {
        var clone = new MessageScriptLibraryFunction();
        clone.Index = Index;
        clone.Name = Name;
        clone.Description = Description;
        clone.Semantic = Semantic;
        clone.Parameters = Parameters.Clone()?.ToList();
        return clone;
    }
}

public enum MessageScriptLibraryFunctionSemantic
{
    Normal,
    Unused
}