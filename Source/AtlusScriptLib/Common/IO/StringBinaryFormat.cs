using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.IO
{
    public enum StringBinaryFormat
    {
        Unknown,
        NullTerminated,
        FixedLength,
        PrefixedLength8,
        PrefixedLength16,
        PrefixedLength32,
    }
}
