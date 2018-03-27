using System;
using System.Collections.Generic;
using System.Linq;
using AtlusScriptLibrary.Common.Libraries;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler
{
    internal class IntrinsicSupport
    {
        // Function indcies
        public short PrintIntFunctionIndex { get; }

        public short PrintStringFunctionIndex { get; }

        public short PrintFloatFunctionIndex { get; }

        public short AiGetLocalFunctionIndex { get; }

        public short AiSetLocalFunctionIndex { get; }

        public short AiGetGlobalFunctionIndex { get; }

        public short AiSetGlobalFunctionIndex { get; }

        public short BitCheckFunctionIndex { get; }

        public short BitOnFunctionIndex { get; }

        public short BitOffFunctionIndex { get; }

        // Support flags
        public bool SupportsTrace { get; }

        public bool SupportsAiLocal { get; }

        public bool SupportsAiGlobal { get; }

        public bool SupportsBit { get; }


        public IntrinsicSupport( Library registry )
        {
            if ( registry == null )
                return;

            var functions = registry.FlowScriptModules.SelectMany( x => x.Functions )
                                    .ToDictionary( x => x.Name, StringComparer.InvariantCultureIgnoreCase );

            PrintIntFunctionIndex = GetIndex( functions, "PUT" );
            PrintStringFunctionIndex = GetIndex( functions, "PUTS" );
            PrintFloatFunctionIndex = GetIndex( functions, "PUTF" );
            SupportsTrace = PrintIntFunctionIndex != -1 && PrintStringFunctionIndex != -1 && PrintFloatFunctionIndex != -1;

            AiGetLocalFunctionIndex = GetIndex( functions, "AI_GET_LOCAL_PARAM" );
            AiSetLocalFunctionIndex = GetIndex( functions, "AI_SET_LOCAL_PARAM" );
            SupportsAiLocal = AiGetLocalFunctionIndex != -1 && AiSetLocalFunctionIndex != -1;

            AiGetGlobalFunctionIndex = GetIndex( functions, "AI_GET_GLOBAL" );
            AiSetGlobalFunctionIndex = GetIndex( functions, "AI_SET_GLOBAL" );
            SupportsAiGlobal = AiGetGlobalFunctionIndex != -1 && AiSetGlobalFunctionIndex != -1;

            BitCheckFunctionIndex = GetIndex( functions, "BIT_CHK" );
            BitOnFunctionIndex = GetIndex( functions, "BIT_ON" );
            BitOffFunctionIndex = GetIndex( functions, "BIT_OFF" );
            SupportsBit = BitCheckFunctionIndex != -1 && BitOnFunctionIndex != -1 && BitOffFunctionIndex != -1;
        }

        private static short GetIndex( Dictionary< string, FlowScriptModuleFunction > dictionary, string name )
        {
            if ( !dictionary.TryGetValue( name, out var function ) )
                return -1;

            return (short)function.Index;
        }
    }
}
