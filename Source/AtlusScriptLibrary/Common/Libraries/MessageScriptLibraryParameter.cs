using System;

namespace AtlusScriptLibrary.Common.Libraries;

public class MessageScriptLibraryParameter : ICloneable
{
    public string Name { get; set; }

    public string Description { get; set; }

    public object Clone()
    {
        var clone = new MessageScriptLibraryParameter();
        clone.Name = Name;
        clone.Description = Description;
        return clone;
    }
}