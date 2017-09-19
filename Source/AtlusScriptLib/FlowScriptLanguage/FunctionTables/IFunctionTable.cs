using System.Collections.Generic;

namespace AtlusScriptLib.FlowScriptLanguage.FunctionTables
{
    public interface IFunctionTable
    {
        Dictionary<int, FunctionTableEntry> Entries { get; }

        FunctionTableEntry this[int index] { get; }
    }
}
