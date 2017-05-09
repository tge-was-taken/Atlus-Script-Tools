using System.Collections.Generic;

namespace AtlusScriptLib.FlowScript.CommTables
{
    public interface ICommTable
    {
        Dictionary<int, CommTableEntry> Entries { get; }

        CommTableEntry this[int index] { get; }
    }
}
