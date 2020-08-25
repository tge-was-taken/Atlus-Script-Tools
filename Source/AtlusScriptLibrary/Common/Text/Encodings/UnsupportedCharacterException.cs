using System;
using System.Text;

namespace AtlusScriptLibrary.Common.Text.Encodings
{
    public class UnsupportedCharacterException : Exception
    {
        public string EncodingName { get; }

        public string Character { get; }

        public UnsupportedCharacterException( string encodingName, string c )
            : base( $"Encoding {encodingName} does not support character: {c} ({EncodeNonAsciiCharacters(c)})" )
        {
            EncodingName = encodingName;
            Character    = c;
        }

        static string EncodeNonAsciiCharacters(string value)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in value)
            {
                if (c > 127)
                {
                    // This character is too big for ASCII
                    string encodedValue = "\\u" + ((int)c).ToString("x4");
                    sb.Append(encodedValue);
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }
    }
}