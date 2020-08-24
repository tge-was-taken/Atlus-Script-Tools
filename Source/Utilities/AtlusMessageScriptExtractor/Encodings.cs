using System.Collections.Generic;
using System.Text;
using AtlusScriptLibrary.Common.Text.Encodings;

namespace AtlusMessageScriptExtractor
{
    public static class Encodings
    {
        public static Encoding ShiftJisEncoding = ShiftJISEncoding.Instance;

        public static Encoding P3Encoding = AtlusEncoding.Persona3;

        public static Encoding P4Encoding = AtlusEncoding.Persona4;

        public static Encoding P5Encoding = AtlusEncoding.Persona5;

        public static Dictionary<string, Encoding> EncodingByName = new Dictionary<string, Encoding>
        {
            { "sj", ShiftJisEncoding },
            { "p3", P3Encoding },
            { "p4", P4Encoding },
            { "p5", P5Encoding }
        };
    }
}
