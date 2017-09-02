using AtlusScriptLib.BinaryModel;

namespace AtlusScriptLib
{
    /// <summary>
    /// Represents the message script message types.
    /// </summary>
    public enum MessageScriptWindowType
    {
        Dialogue = MessageScriptBinaryMessageType.Dialogue,
        Selection = MessageScriptBinaryMessageType.Selection
    }

    /// <summary>
    /// Represents the message script token types.
    /// </summary>
    public enum MessageScriptTokenType
    {
        Text,
        Function,
        CodePoint,
        NewLine,
    }

    /// <summary>
    /// Represents the dialogue message speaker types.
    /// </summary>
    public enum MessageScriptSpeakerType
    {
        Named,
        VariablyNamed,
    }
}