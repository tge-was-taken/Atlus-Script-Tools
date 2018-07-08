using System;

namespace AtlusScriptLibrary.Common.Text.Encodings
{
    public class UnsupportedCharacterException : Exception
    {
        public string EncodingName { get; }

        public char Character { get; }

        public UnsupportedCharacterException( string encodingName, char c )
        {
            EncodingName = encodingName;
            Character    = c;
        }
    }
}