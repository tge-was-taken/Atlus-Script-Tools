using AtlusScriptLibrary.FlowScriptLanguage.BinaryModel;

namespace AtlusScriptLibrary.FlowScriptLanguage
{
    /// <summary>
    /// Represents the opcodes in a flow script.
    /// </summary>
    public enum Opcode : ushort
    {
        /// <summary>
        /// Push integer value to the stack.
        /// </summary>
        PUSHI,

        /// <summary>
        /// Push float value to the stack.
        /// </summary>
        PUSHF,

        /// <summary>
        /// Push the value of a global indexed integer to the stack.
        /// </summary>
        PUSHIX,

        /// <summary>
        /// Push the value of a global indexed float to the stack.
        /// </summary>
        PUSHIF,

        /// <summary>
        /// Push the value of the register to the stack. Used to store COMM return values.
        /// </summary>
        PUSHREG,

        /// <summary>
        /// Pop a value off the stack and assign it to a global indexed integer.
        /// </summary>
        POPIX,

        /// <summary>
        /// Pop a value off the stack and assingn it to a global indexed float.
        /// </summary>
        POPFX,

        /// <summary>
        /// Start of procedure.
        /// </summary>
        PROC,

        /// <summary>
        /// Communicate with game through calling a native registered function.
        /// </summary>
        COMM,

        /// <summary>
        /// Jumps to the return address.
        /// </summary>
        END,

        /// <summary>
        /// Jump to jump label.
        /// </summary>
        JUMP,

        /// <summary>
        /// Call to procedure.
        /// </summary>
        CALL,

        /// <summary>
        /// Run script. Not supported by any game.
        /// </summary>
        RUN,

        /// <summary>
        /// Go to label.
        /// </summary>
        GOTO,

        /// <summary>
        /// Add 2 values by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        ADD,

        /// <summary>
        /// Subtract 2 values by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        SUB,

        /// <summary>
        /// Multiply 2 values by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        MUL,

        /// <summary>
        /// Divide 2 values by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        DIV,

        /// <summary>
        /// Negate one value by popping it off the stack and pushing the return value to the stack.
        /// </summary>
        MINUS,

        /// <summary>
        /// Logical NOT one value by popping it off the stack and pushing the return value to the stack.
        /// </summary>
        NOT,

        /// <summary>
        /// Logical OR 2 values by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        OR,

        /// <summary>
        /// Logical AND 2 values by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        AND,

        /// <summary>
        /// Check 2 values for equality by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        EQ,

        /// <summary>
        /// Check 2 values for non-equality by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        NEQ,

        /// <summary>
        /// Check if the first value is smaller than the second value by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        S,

        /// <summary>
        /// Check if the first value is larger than the second value by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        L,

        /// <summary>
        /// Check if the first value is smaller than or equal to the second value by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        SE,

        /// <summary>
        /// Check if the first value is larger than or equal to the second value by popping them off the stack and pushing the return value to the stack.
        /// </summary>
        LE,

        /// <summary>
        /// Jump to label if value ontop of the stack is true, enter a branch of it is false.
        /// </summary>
        IF,

        /// <summary>
        /// Push a short integer value to the stack.
        /// </summary>
        PUSHIS,

        /// <summary>
        /// Push the value of a local indexed int to the stack.
        /// </summary>
        PUSHLIX,

        /// <summary>
        /// Push the value of a local indexed float to the stack.
        /// </summary>
        PUSHLFX,

        /// <summary>
        /// Pop a value off the stack and assign it to a local indexed integer.
        /// </summary>
        POPLIX,

        /// <summary>
        /// Pop a value off the stack and assign it to a local indexed float.
        /// </summary>
        POPLFX,

        /// <summary>
        /// Push a string value to the stack by pushing the index of the string in the string table.
        /// </summary>
        PUSHSTR
    }

    public enum FormatVersion : uint
    {
        Unknown = BinaryFormatVersion.Unknown,
        Version1 = BinaryFormatVersion.Version1,
        Version1BigEndian = BinaryFormatVersion.Version1BigEndian,
        Version2 = BinaryFormatVersion.Version2,
        Version2BigEndian = BinaryFormatVersion.Version2BigEndian,
        Version3 = BinaryFormatVersion.Version3,
        Version3BigEndian = BinaryFormatVersion.Version3BigEndian,
    }
}
