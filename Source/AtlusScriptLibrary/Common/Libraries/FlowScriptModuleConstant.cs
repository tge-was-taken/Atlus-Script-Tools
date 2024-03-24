using System;

namespace AtlusScriptLibrary.Common.Libraries;

public class FlowScriptModuleConstant : ICloneable
{
    public string Name { get; set; }

    public string Description { get; set; }

    public string Type { get; set; }

    public string Value { get; set; }

    public object Clone()
    {
        var clone = new FlowScriptModuleConstant();
        clone.Name = Name;
        clone.Description = Description;
        clone.Type = Type;
        clone.Value = Value;
        return clone;
    }
}