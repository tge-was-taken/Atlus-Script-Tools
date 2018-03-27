namespace AtlusScriptLibrary.Common.Text.Encodings
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
