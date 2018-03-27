using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

namespace AtlusScriptLibrary.MessageScriptLanguage
{
    /// <summary>
    /// Represents the message script message types.
    /// </summary>
    public enum DialogKind
    {
        Message = BinaryDialogKind.Message,
        Selection = BinaryDialogKind.Selection
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
    public enum SpeakerKind
    {
        Named,
        Variable
    }

    public enum FormatVersion : uint
    {
        Detect,
        Version1 = BinaryFormatVersion.Version1,
        Version1DDS = BinaryFormatVersion.Version1DDS,
        Version1BigEndian = BinaryFormatVersion.Version1BigEndian
    }
}