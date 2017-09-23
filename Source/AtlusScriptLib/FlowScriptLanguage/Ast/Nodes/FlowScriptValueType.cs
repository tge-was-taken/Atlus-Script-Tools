namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public enum FlowScriptValueType
    {
        /// <summary>
        /// Indicates a value whose type is unresolved at parse time.
        /// </summary>
        Unresolved,

        /// <summary>
        /// Indicates a value that represents a type reference.
        /// </summary>
        Type,

        /// <summary>
        /// Indicates a value that represents a function reference.
        /// </summary>
        Function,

        /// <summary>
        /// Indicates a value that represents a procedure reference.
        /// </summary>
        Procedure,

        /// <summary>
        /// Indicates a value that represents a variable reference.
        /// </summary>
        Variable,

        /// <summary>
        /// Used for functions or procedures that don't return a value.
        /// </summary>
        Void,

        /// <summary>
        /// Boolean primitive value type.
        /// </summary>
        Bool,

        /// <summary>
        /// Integer primitive value type.
        /// </summary>
        Int,

        /// <summary>
        /// Float primitive value type.
        /// </summary>
        Float,

        /// <summary>
        /// String primitive value type. Not a valid type for a variable, but can be used as the type for a parameter to a function (but not a procedure).
        /// </summary>
        String,
    }
}
