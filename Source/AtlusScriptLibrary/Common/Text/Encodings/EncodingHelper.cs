using AtlusScriptLibrary.Common.IO;
using System.Text;

namespace AtlusScriptLibrary.Common.Text.Encodings;

public class EncodingHelper
{
    public static Encoding GetEncodingForEndianness(Encoding encoding, bool isBigEndian)
    {
        if (encoding == Encoding.Unicode)
        {
            if (isBigEndian)
                return Encoding.BigEndianUnicode;
        }
        else if (encoding is CustomUnicodeEncoding cue)
        {
            return cue.GetEncodingForEndianness(isBigEndian);
        }

        return encoding;
    }
}
