using System.Collections.Generic;
using AtlusScriptLib.Common.Collections;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public static class FlowScriptKeywordConverter
    {
        public static readonly Dictionary<FlowScriptValueType, string> ValueTypeToKeyword = new Dictionary<FlowScriptValueType, string>()
        {
            { FlowScriptValueType.Void,         "void" },
            { FlowScriptValueType.Bool,         "bool" },
            { FlowScriptValueType.Int,          "int" },
            { FlowScriptValueType.Float,        "float" },
            { FlowScriptValueType.String,       "string" }
        };

        public static readonly Dictionary< string, FlowScriptValueType > KeywordToValueType = ValueTypeToKeyword.Reverse();

        public static readonly Dictionary<FlowScriptModifierType, string> ModifierTypeToKeyword = new Dictionary<FlowScriptModifierType, string>()
        {
            { FlowScriptModifierType.Static,        "static" },
            { FlowScriptModifierType.Constant,      "const" }
        };

        public static readonly Dictionary<string, FlowScriptModifierType> KeywordToModifierType = ModifierTypeToKeyword.Reverse();
    }
}
