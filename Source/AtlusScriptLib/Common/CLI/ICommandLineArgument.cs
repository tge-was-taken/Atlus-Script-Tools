using System;
using System.Collections.Generic;

namespace AtlusScriptLib.Common.CLI
{
    public interface ICommandLineArgument
    {
        bool TakesParameters { get; set; }
        bool IsValueProvided { get; set; }
        IConvertible DefaultValue { get; set; }
        string Description { get; set; }
        string Key { get; }
        List<IConvertible> PossibleValues { get; set; }
        bool Required { get; set; }
        IConvertible Value { get; set; }
    }
}