using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.Text.Encodings
{
    public struct CodePoint
    {
        public byte HighSurrogate;
        public byte LowSurrogate;

        public CodePoint( byte high, byte low )
        {
            HighSurrogate = high;
            LowSurrogate = low;
        }
    }
}
