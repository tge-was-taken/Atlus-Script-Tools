using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler
{
    public static class NameFormatter
    {
        public static string GenerateVariableName( VariableModifierKind modifier, ValueKind kind, short index, bool isTopLevel )
        {
            switch ( kind )
            {
                case ValueKind.Int:
                    switch ( modifier )
                    {
                        case VariableModifierKind.Local:
                            return isTopLevel ? $"sVar{index}" : $"var{index}";
                        case VariableModifierKind.Global:
                            return isTopLevel ? $"gVar{index}" : $"gVar{index}";
                    }
                    break;
                case ValueKind.Float:
                    switch ( modifier )
                    {
                        case VariableModifierKind.Local:
                            return isTopLevel ? $"sfVar{index}" : $"fVar{index}";
                        case VariableModifierKind.Global:
                            return isTopLevel ? $"gfVar{index}" : $"gfVar{index}";
                    }
                    break;
            }

            Debug.Assert( false );
            return null;
        }

        public static string GenerateParameterName( ValueKind kind, int index )
        {
            switch ( kind )
            {
                case ValueKind.Int:
                    return $"param{index}";
                case ValueKind.Float:
                    return $"fParam{index}";
            }

            Debug.Assert( false );
            return null;
        }
    }
}
