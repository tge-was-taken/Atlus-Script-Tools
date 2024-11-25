using AtlusScriptLibrary.Common.Libraries;
using System;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler;

internal class IntrinsicSupport
{
    // Function indcies
    public ushort PrintIntFunctionIndex { get; }

    public ushort PrintStringFunctionIndex { get; }

    public ushort PrintFloatFunctionIndex { get; }

    public ushort AiGetLocalFunctionIndex { get; }

    public ushort AiSetLocalFunctionIndex { get; }

    public ushort AiGetGlobalFunctionIndex { get; }

    public ushort AiSetGlobalFunctionIndex { get; }

    public ushort BitCheckFunctionIndex { get; }

    public ushort BitOnFunctionIndex { get; }

    public ushort BitOffFunctionIndex { get; }

    public ushort GetCountFunctionIndex { get; }
    public ushort SetCountFunctionIndex { get; }

    // Support flags
    public bool SupportsTrace { get; }

    public bool SupportsAiLocal { get; }

    public bool SupportsAiGlobal { get; }

    public bool SupportsBit { get; }
    public bool SupportsCount { get; }

    public IntrinsicSupport(Library registry)
    {
        if (registry == null)
            return;

        var functions = registry.FlowScriptModules.SelectMany(x => x.Functions)
                                .ToDictionary(x => x.Name, StringComparer.InvariantCultureIgnoreCase);

        PrintIntFunctionIndex = GetIndex(functions, "PUT");
        PrintStringFunctionIndex = GetIndex(functions, "PUTS");
        PrintFloatFunctionIndex = GetIndex(functions, "PUTF");
        SupportsTrace = PrintIntFunctionIndex != 0xffff && PrintStringFunctionIndex != 0xffff && PrintFloatFunctionIndex != 0xffff;

        AiGetLocalFunctionIndex = GetIndex(functions, "AI_GET_LOCAL_PARAM");
        AiSetLocalFunctionIndex = GetIndex(functions, "AI_SET_LOCAL_PARAM");
        SupportsAiLocal = AiGetLocalFunctionIndex != 0xffff && AiSetLocalFunctionIndex != 0xffff;

        AiGetGlobalFunctionIndex = GetIndex(functions, "AI_GET_GLOBAL");
        AiSetGlobalFunctionIndex = GetIndex(functions, "AI_SET_GLOBAL");
        SupportsAiGlobal = AiGetGlobalFunctionIndex != 0xffff && AiSetGlobalFunctionIndex != 0xffff;

        BitCheckFunctionIndex = GetIndex(functions, "BIT_CHK");
        BitOnFunctionIndex = GetIndex(functions, "BIT_ON");
        BitOffFunctionIndex = GetIndex(functions, "BIT_OFF");
        SupportsBit = BitCheckFunctionIndex != 0xffff && BitOnFunctionIndex != 0xffff && BitOffFunctionIndex != 0xffff;

        GetCountFunctionIndex = GetIndex(functions, "GET_COUNT");
        SetCountFunctionIndex = GetIndex(functions, "SET_COUNT");
        SupportsCount = GetCountFunctionIndex != 0xffff && SetCountFunctionIndex != 0xffff;
    }

    private static ushort GetIndex(Dictionary<string, FlowScriptModuleFunction> dictionary, string name)
    {
        if (!dictionary.TryGetValue(name, out var function))
            return 0xffff;

        return (ushort)function.Index;
    }
}
