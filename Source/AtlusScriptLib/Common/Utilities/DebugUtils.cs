using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace AtlusScriptLib.Common.Utilities
{
    internal static class DebugUtils
    {
        [Conditional("DEBUG")]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void DebugBreak()
        {
            if (Debugger.IsAttached)
            {
                Debugger.Break();
            }
        }

        [Conditional("TRACE")]
        public static void TraceWarning(string errorMessage)
        {
            DebugBreak();
            Trace.TraceWarning(errorMessage);
        }

        [Conditional("TRACE")]
        public static void TraceError(string errorMessage)
        {         
            DebugBreak();
            Trace.TraceError(errorMessage);
        }

        public static void FatalException(string errorMessage)
        {
            DebugBreak();
            throw new System.Exception(errorMessage);
        }
    }
}
