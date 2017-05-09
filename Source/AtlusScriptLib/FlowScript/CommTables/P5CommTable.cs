using System.Collections.Generic;

namespace AtlusScriptLib.FlowScript.CommTables
{
    public class CommTable : ICommTable
    {
        public Dictionary<int, CommTableEntry> Entries { get; }

        public CommTableEntry this[int index]
        {
            get { return Entries[index]; }
            set { Entries[index] = value; }
        }

        public CommTable(string path)
        {
            Entries = CommTableParser.Parse(path);
        }
    }

    public class P5CommTable : ICommTable
    {
        public static CommTable Instance { get; }

        static P5CommTable()
        {
            Instance = new CommTable("FlowScript\\CommTables\\p5table.txt");
        }

        public Dictionary<int, CommTableEntry> Entries { get; }

        public CommTableEntry this[int index]
        {
            get { return Entries[index]; }
            set { Entries[index] = value; }
        }
    }
}
