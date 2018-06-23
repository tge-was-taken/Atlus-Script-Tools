namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public enum ValueKind
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
        /// Indicates a value that represents a label reference.
        /// </summary>
        Label,

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

        /// <summary>
        /// Null value type. Special type.
        /// </summary>
        Null
    }

    public static class ValueKindExtensions
    {
        /// <summary>
        /// Get the underlying base value kind.
        /// </summary>
        /// <param name="valueKind"></param>
        /// <returns></returns>
        public static ValueKind GetBaseKind( this ValueKind valueKind )
        {
            switch ( valueKind )
            {
                case ValueKind.Bool:
                case ValueKind.Int:
                case ValueKind.String: // index of string in string table
                    return ValueKind.Int;

                case ValueKind.Float:
                    return ValueKind.Float;
            }

            return valueKind;
        }
    }
}
