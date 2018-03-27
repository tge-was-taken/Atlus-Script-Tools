using System.Runtime.CompilerServices;

namespace AtlusScriptLibrary.Common.IO
{
    public static class AlignmentHelper
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long Align(long value, int alignment)
        {
            return (value + (alignment - 1)) & ~(alignment - 1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int Align(int value, int alignment)
        {
            return (value + (alignment - 1)) & ~(alignment - 1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetAlignedDifference(long value, int alignment)
        {
            return (int)(((value + (alignment - 1)) & ~(alignment - 1)) - value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetAlignedDifference(int value, int alignment)
        {
            return ((value + (alignment - 1)) & ~(alignment - 1)) - value;
        }
    }
}
