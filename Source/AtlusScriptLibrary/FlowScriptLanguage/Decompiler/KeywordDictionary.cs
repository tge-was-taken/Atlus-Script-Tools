using System.Collections.Generic;
using AtlusScriptLibrary.Common.Collections;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler
{
    public static class KeywordDictionary
    {
        public static Dictionary< ValueKind, string > ValueTypeToKeyword { get; } = new Dictionary< ValueKind, string >
        {
            { ValueKind.Void, "void" },
            { ValueKind.Bool, "bool" },
            { ValueKind.Int, "int" },
            { ValueKind.Float, "float" },
            { ValueKind.String, "string" }
        };

        public static Dictionary< string, ValueKind > KeywordToValueType { get; } = ValueTypeToKeyword.Reverse();

        public static Dictionary< VariableModifierKind, string > ModifierTypeToKeyword { get; } = new Dictionary< VariableModifierKind, string >
        {
            { VariableModifierKind.Global, "global" },
            { VariableModifierKind.Constant, "const" },
            { VariableModifierKind.AiLocal, "ai_local"},
            { VariableModifierKind.AiGlobal, "ai_global" },
            { VariableModifierKind.Bit, "bit" }
        };

        public static Dictionary< string, VariableModifierKind > KeywordToModifierType { get; } = ModifierTypeToKeyword.Reverse();
    }
}
