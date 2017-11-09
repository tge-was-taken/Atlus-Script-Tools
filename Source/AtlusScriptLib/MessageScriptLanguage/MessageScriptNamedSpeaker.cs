namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Represents a named dialogue message speaker.
    /// </summary>
    public sealed class MessageScriptNamedSpeaker : IMessageScriptSpeaker
    {
        /// <summary>
        /// Gets the name of the speaker.
        /// </summary>
        public MessageScriptLine Name { get; }

        /// <summary>
        /// Constructs a new speaker.
        /// </summary>
        /// <param name="name">The name of the speaker.</param>
        public MessageScriptNamedSpeaker( MessageScriptLine name )
        {
            Name = name;
        }

        public MessageScriptNamedSpeaker( string name )
        {
            Name = new MessageScriptLineBuilder()
                .AddText( name )
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
                {
                    str += token.ToString() + " ";
                }
            }

            return str;
        }

        /// <summary>
        /// Gets the speaker type.
        /// </summary>
        MessageScriptSpeakerType IMessageScriptSpeaker.Type => MessageScriptSpeakerType.Named;
    }
}