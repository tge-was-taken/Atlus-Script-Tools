namespace AtlusScriptLibrary.MessageScriptLanguage
{
    public sealed class VariableSpeaker : ISpeaker
    {
        /// <summary>
        /// Gets the index of the speaker name variable.
        /// </summary>
        public int Index { get; }

        /// <summary>
        /// Constructs a new variable speaker.
        /// </summary>
        /// <param name="index">The index of the speaker name variable.</param>
        public VariableSpeaker( int index )
        {
            Index = index;
        }

        /// <summary>
        /// Converts this speaker to its string representation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"<variable name {Index}>";
        }

        /// <summary>
        /// Gets the speaker type.
        /// </summary>
        SpeakerKind ISpeaker.Kind => SpeakerKind.Variable;
    }
}