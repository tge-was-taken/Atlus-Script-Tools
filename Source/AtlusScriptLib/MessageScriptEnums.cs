namespace AtlusScriptLib
{
    public enum MessageScriptMessageType
    {
        Dialogue    = MessageScriptBinaryMessageType.Dialogue,
        Selection   = MessageScriptBinaryMessageType.Selection
    }

    public enum MessageScriptTokenType
    {
        Text,
        Function,
        CharacterCode
    }
}