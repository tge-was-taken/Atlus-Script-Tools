namespace AtlusScriptLib
{
    /// <summary>
    /// Common interface for dialogue message speakers.
    /// </summary>
    public interface IMessageScriptSpeaker
    {
        /// <summary>
        /// Gets the speaker type.
        /// </summary>
        MessageScriptSpeakerType Type { get; }
    }
}