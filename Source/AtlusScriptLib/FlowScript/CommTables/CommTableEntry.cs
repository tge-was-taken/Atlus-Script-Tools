using AtlusScriptLib.Shared.Syntax;

namespace AtlusScriptLib.FlowScript.CommTables
{
    public struct CommTableEntry
    {
        public int Id { get; }

        public FunctionDeclaration Declaration { get; }

        public bool IsUnused { get; }

        public CommTableEntry(int id, FunctionDeclaration declaration, bool unused)
        {
            Id = id;
            Declaration = declaration;
            IsUnused = unused;
        }
    }
}
