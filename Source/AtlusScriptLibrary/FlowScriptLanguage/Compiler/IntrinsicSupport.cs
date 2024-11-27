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
        SupportsTrace = PrintIntFunctionIndex != ushort.MaxValue && PrintStringFunctionIndex != ushort.MaxValue && PrintFloatFunctionIndex != ushort.MaxValue;

        AiGetLocalFunctionIndex = GetIndex(functions, "AI_GET_LOCAL_PARAM");
        AiSetLocalFunctionIndex = GetIndex(functions, "AI_SET_LOCAL_PARAM");
        SupportsAiLocal = AiGetLocalFunctionIndex != ushort.MaxValue && AiSetLocalFunctionIndex !=   ushort.MaxValue;

        AiGetGlobalFunctionIndex = GetIndex(functions, "AI_GET_GLOBAL");
        AiSetGlobalFunctionIndex = GetIndex(functions, "AI_SET_GLOBAL");
        SupportsAiGlobal = AiGetGlobalFunctionIndex != ushort.MaxValue && AiSetGlobalFunctionIndex != ushort.MaxValue;

        BitCheckFunctionIndex = GetIndex(functions, "BIT_CHK");
        BitOnFunctionIndex = GetIndex(functions, "BIT_ON");
        BitOffFunctionIndex = GetIndex(functions, "BIT_OFF");
        SupportsBit = BitCheckFunctionIndex != ushort.MaxValue && BitOnFunctionIndex != ushort.MaxValue && BitOffFunctionIndex != ushort.MaxValue;

        GetCountFunctionIndex = GetIndex(functions, "GET_COUNT");
        SetCountFunctionIndex = GetIndex(functions, "SET_COUNT");
        SupportsCount = GetCountFunctionIndex != ushort.MaxValue && SetCountFunctionIndex != ushort.MaxValue;
    }

    private static ushort GetIndex(Dictionary<string, FlowScriptModuleFunction> dictionary, string name)
    {
        if (!dictionary.TryGetValue(name, out var function))
            return ushort.MaxValue;

        return (ushort)function.Index;
    }
}
