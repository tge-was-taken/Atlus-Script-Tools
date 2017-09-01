namespace AtlusScriptLib
{
    public struct MessageScriptCodePointToken : IMessageScriptLineToken
    {
        public byte HighSurrogate { get; }

        public byte LowSurrogate { get; }

        public MessageScriptCodePointToken( byte high, byte low )
        {
            HighSurrogate = high;
            LowSurrogate = low;
        }

        MessageScriptTokenType IMessageScriptLineToken.Type => MessageScriptTokenType.CodePoint;

        public override string ToString()
        {
            return $"[{HighSurrogate:X2} {LowSurrogate:X2}]";
        }
    }
}
