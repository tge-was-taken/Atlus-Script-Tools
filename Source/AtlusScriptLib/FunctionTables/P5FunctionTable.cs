namespace AtlusScriptLib.FunctionTables
{
    public class P5FunctionTable : FunctionTable
    {
        public static FunctionTable Instance { get; }

        static P5FunctionTable()
        {
            Instance = new FunctionTable("FunctionTables\\p5table.txt");
        }

        private P5FunctionTable()
        {
        }
    }
}
