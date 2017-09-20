using AtlusScriptLib.MessageScriptLanguage.BinaryModel;

namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents the message script message types.
    /// </summary>
    public enum MessageScriptWindowType
    {
        Dialogue = MessageScriptBinaryWindowType.Dialogue,
        Selection = MessageScriptBinaryWindowType.Selection
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
        Variable,
    }

    public enum MessageScriptFormatVersion : uint
    {
        Version1 = MessageScriptBinaryFormatVersion.Version1,
        Version1BigEndian = MessageScriptBinaryFormatVersion.Version1BigEndian,
    }
}