using System;

namespace AtlusScriptLib.FlowScript
{
    public enum FlowScriptBinarySectionType : uint
    {
        ProcedureLabelSection,
        JumpLabelSection,
        TextSection,
        MessageScriptSection,
        StringSection,
    }

    public enum FlowScriptBinaryLoadResult
    {  
        Unknown,
        OK,
        InvalidFormat,
    }

    [Flags]
    public enum FlowScriptBinaryVersion
    {
        Unknown     = 1 << 0,
        V1          = 1 << 1,
        V2          = 1 << 2,
        V3          = 1 << 3,
        BE          = 1 << 15,
        V1_BE       = V1 | BE,     
        V2_BE       = V2 | BE,
        V3_BE       = V3 | BE,
    }
    public enum FlowScriptBinaryOpcode : ushort
    {
        PUSHI,
        PUSHF,
        PUSHIX,
        PUSHIF,
        PUSHREG,
        POPIX,
        POPFX,
        PROC,
        COMM,
        END,
        JUMP,
        CALL,
        RUN,
        GOTO,
        ADD,
        SUB,
        MUL,
        DIV,
        MINUS,
        NOT,
        OR,
        AND,
        EQ,
        NEQ,
        S,
        L,
        SE,
        LE,
        IF,
        PUSHIS,
        PUSHLIX,
        PUSHLFX,
        POPLIX,
        POPLFX,
        PUSHSTR
    }
}
