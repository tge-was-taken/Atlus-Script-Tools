using System.Collections.Generic;

namespace AtlusScriptLib.FunctionTables
{
    public class FunctionTable : IFunctionTable
    {
        public Dictionary<int, FunctionTableEntry> Entries { get; }

        public FunctionTableEntry this[int index]
        {
            get { return Entries[index]; }
            set { Entries[index] = value; }
        }

        protected FunctionTable()
        {
        }

        public FunctionTable( string path )
        {
            Entries = FunctionTableParser.Parse( path );
        }
    }
}
