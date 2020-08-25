using System;

namespace AtlusScriptLibrary.Common.Text.Encodings
{
    public class UnsupportedCharacterException : Exception
    {
        public string EncodingName { get; }

        public string Character { get; }

        public UnsupportedCharacterException( string encodingName, string c )
            : base( $"Encoding {encodingName} does not support character: {c}" )
        {
            EncodingName = encodingName;
            Character    = c;
        }
    }
}