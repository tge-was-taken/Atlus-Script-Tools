using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.IO
{
    public static class Bitwise
    {
        public static uint GenerateBitmask(int bitCount)
        {
            return GenerateBitmask(0, bitCount - 1);
        }

        public static uint GenerateBitmask(int from, int to)
        {
            uint mask = 0;
            for (int i = from; i < (to + 1); i++)
                mask |= (1u << i);

            return mask;
        }

        public static uint Clear(uint value, int bitCount)
        {
            return Clear(value, 0, bitCount - 1);
        }

        public static uint Clear(uint value, int from, int to)
        {
            return value & ~GenerateBitmask(from, to);
        }

        public static uint Extract(uint value, int bitCount)
        {
            return Extract(value, 0, bitCount - 1);
        }

        public static uint Extract(uint value, int from, int to)
        {
            var mask = GenerateBitmask(from, to);
            return (value & mask) >> from;
        }

        public static uint Pack(uint destination, uint value, int from, int to)
        {
            return Clear(destination, from, to) | Extract(value, from, to);
        }

        public static bool IsBitSet(uint value, int bit)
        {
            return (value & 1u << bit) == 1;
        }

        public static bool AreBitsSet(uint value, uint bitMask)
        {
            return (value & bitMask) == bitMask;
        }

        public static uint ToggleBit(uint value, int bit)
        {
            return value | ~(value & 1u << bit);
        }

        public static uint ToggleBits(uint value, uint bitMask)
        {
            return value | ~(value & bitMask);
        }
    }
}
