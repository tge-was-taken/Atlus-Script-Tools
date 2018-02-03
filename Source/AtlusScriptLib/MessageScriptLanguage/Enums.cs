using AtlusScriptLib.MessageScriptLanguage.BinaryModel;

namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents the message script message types.
    /// </summary>
    public enum WindowType
    {
        Dialogue = BinaryWindowType.Dialogue,
        Selection = BinaryWindowType.Selection
    }

    /// <summary>
    /// Represents the message script token types.
    /// </summary>
    public enum TokenKind
    {
        String,
        Function,
        CodePoint,
        NewLine
    }

    /// <summary>
    /// Represents the dialogue message speaker types.
    /// </summary>
    public enum SpeakerType
    {
        Named,
        Variable
    }

    public enum FormatVersion : uint
    {
        Version1 = BinaryFormatVersion.Version1,
        Version1BigEndian = BinaryFormatVersion.Version1BigEndian
    }
}