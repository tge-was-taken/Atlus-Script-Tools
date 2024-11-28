using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using System;
using System.Diagnostics;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler;

public static class NameFormatter
{
    public static string GenerateVariableName(VariableModifierKind modifier, ValueKind kind, ushort index, bool isTopLevel)
    {
        switch (kind)
        {
            case ValueKind.Int:
                switch (modifier)
                {
                    case VariableModifierKind.Local:
                        return isTopLevel ? $"sVar{index}" : $"var{index}";
                    case VariableModifierKind.Global:
                        return isTopLevel ? $"gVar{index}" : $"gVar{index}";
                }
                break;
            case ValueKind.Float:
                switch (modifier)
                {
                    case VariableModifierKind.Local:
                        return isTopLevel ? $"sfVar{index}" : $"fVar{index}";
                    case VariableModifierKind.Global:
                        return isTopLevel ? $"gfVar{index}" : $"gfVar{index}";
                }
                break;
        }

        throw new NotImplementedException($"Generating variable name for modifier {modifier}, kind {kind} not implemented");
    }

    public static string GenerateParameterName(ValueKind kind, int index)
    {
        switch (kind)
        {
            case ValueKind.Int:
                return $"param{index}";
            case ValueKind.Float:
                return $"fParam{index}";
        }

        throw new NotImplementedException($"Generating parameter name for kind {kind} not implemented");
    }
}
