namespace AtlusScriptLibrary.MessageScriptLanguage
{
    /// <summary>
    /// Common interface for dialogue message speakers.
    /// </summary>
    public interface ISpeaker
    {
        /// <summary>
        /// Gets the speaker type.
        /// </summary>
        SpeakerKind Kind { get; }
    }
}