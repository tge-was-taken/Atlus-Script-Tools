using System;

namespace AtlusScriptLibrary.Common.Text.Encodings
{
    public class UnsupportedCharacterException : Exception
    {
        public string EncodingName { get; }

        public string Character { get; }

        public UnsupportedCharacterException( string encodingName, string c )
        {
            EncodingName = encodingName;
            Character    = c;
        }
    }
}