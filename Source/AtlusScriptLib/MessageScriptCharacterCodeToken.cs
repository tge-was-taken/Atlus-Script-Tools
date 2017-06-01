namespace AtlusScriptLib
{
    public struct MessageScriptCharacterCodeToken : IMessageScriptLineToken
    {
        public ushort Value { get; }

        public MessageScriptCharacterCodeToken(ushort value)
        {
            Value = value;
        }

        MessageScriptTokenType IMessageScriptLineToken.Type => MessageScriptTokenType.CharacterCode;
    }
}
