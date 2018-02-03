namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents a named dialogue message speaker.
    /// </summary>
    public sealed class NamedSpeaker : Speaker
    {
        /// <summary>
        /// Gets the name of the speaker.
        /// </summary>
        public TokenText Name { get; }

        /// <summary>
        /// Constructs a new speaker.
        /// </summary>
        /// <param name="name">The name of the speaker.</param>
        public NamedSpeaker( TokenText name )
        {
            Name = name;
        }

        public NamedSpeaker( string name )
        {
            Name = new TextBuilder()
                .AddString( name )
                .Build();
        }

        /// <summary>
        /// Converts this speaker to its string representation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            string str = string.Empty;

            if ( Name != null && Name.Tokens.Count > 0 )
            {
                foreach ( var token in Name.Tokens )
                    str += token + " ";
            }

            return str;
        }

        /// <summary>
        /// Gets the speaker type.
        /// </summary>
        SpeakerType Speaker.Type => SpeakerType.Named;
    }
}