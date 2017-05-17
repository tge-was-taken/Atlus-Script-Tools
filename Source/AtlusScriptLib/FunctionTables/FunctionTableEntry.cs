using AtlusScriptLib.Common.Syntax;

namespace AtlusScriptLib.FunctionTables
{
    public struct FunctionTableEntry
    {
        public int Id { get; }

        public FunctionDeclaration Declaration { get; }

        public bool IsUnused { get; }

        public FunctionTableEntry(int id, FunctionDeclaration declaration, bool unused)
        {
            Id = id;
            Declaration = declaration;
            IsUnused = unused;
        }
    }
}
