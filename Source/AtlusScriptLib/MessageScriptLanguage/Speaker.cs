namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Common interface for dialogue message speakers.
    /// </summary>
    public interface Speaker
    {
        /// <summary>
        /// Gets the speaker type.
        /// </summary>
        SpeakerType Type { get; }
    }
}