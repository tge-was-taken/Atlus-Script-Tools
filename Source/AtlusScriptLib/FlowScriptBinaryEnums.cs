using System;

namespace AtlusScriptLib
{
    public enum FlowScriptBinarySectionType : uint
    {
        ProcedureLabelSection,
        JumpLabelSection,
        TextSection,
        MessageScriptSection,
        StringSection,
    }

    [Flags]
    public enum FlowScriptBinaryFormatVersion
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
}
