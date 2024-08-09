using System;

namespace AtlusScriptLibrary.Common.Libraries;

public class FlowScriptModuleEnumMember : ICloneable
{
    public string Name { get; set; }

    public int Value { get; set; }

    public string Description { get; set; }

    public object Clone()
    {
        var clone = new FlowScriptModuleEnumMember();
        clone.Name = Name;
        clone.Value = Value;
        clone.Description = Description;
        return clone;
    }
}