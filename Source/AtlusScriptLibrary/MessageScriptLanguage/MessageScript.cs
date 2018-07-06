using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

namespace AtlusScriptLibrary.MessageScriptLanguage
{
    /// <summary>
    /// This class represents a mutable message script that is designed to abstract away the format implementation details.
    /// </summary>
    public class MessageScript
    {
        // TODO: maybe move the parsing functions to a seperate class
        /// <summary>
        /// Creates a <see cref="MessageScript"/> from a <see cref="MessageScriptBinary"/>.
        /// </summary>
        public static MessageScript FromBinary( MessageScriptBinary binary, FormatVersion version = FormatVersion.Detect, Encoding encoding = null )
        {
            if ( binary == null )
                throw new ArgumentNullException( nameof( binary ) );

            if ( binary.DialogHeaders == null )
                throw new ArgumentNullException( nameof( binary ) );

            // Create new script instance & set user id, format version
            var instance = new MessageScript
            {
                Id = binary.Header.UserId,
                FormatVersion = version == FormatVersion.Detect ? ( FormatVersion)binary.FormatVersion : version,
                Encoding = encoding
            };

            // Convert the binary messages to their counterpart
            foreach ( var messageHeader in binary.DialogHeaders )
            {
                IDialog message;
                IReadOnlyList<int> pageStartAddresses;
                IReadOnlyList<byte> buffer;
                int pageCount;

                switch ( messageHeader.DialogKind )
                {
                    case BinaryDialogKind.Message:
                        {
                            var binaryMessage = ( BinaryMessageDialog )messageHeader.Dialog.Value;
                            pageStartAddresses = binaryMessage.PageStartAddresses;
                            buffer = binaryMessage.TextBuffer;
                            pageCount = binaryMessage.PageCount;

                            if ( binaryMessage.SpeakerId == 0xFFFF )
                            {
                                message = new MessageDialog( binaryMessage.Name );
                            }
                            else if ( ( binaryMessage.SpeakerId & 0x8000 ) == 0x8000 )
                            {
                                Trace.WriteLine( binaryMessage.SpeakerId.ToString( "X4" ) );

                                message = new MessageDialog( binaryMessage.Name, new VariableSpeaker( binaryMessage.SpeakerId & 0x0FFF ) );
                            }
                            else
                            {
                                if ( binary.SpeakerTableHeader.SpeakerNameArray.Value == null )
                                    throw new InvalidDataException( "Speaker name array is null while being referenced" );

                                TokenText speakerName = null;
                                if ( binaryMessage.SpeakerId < binary.SpeakerTableHeader.SpeakerCount )
                                {
                                    speakerName = ParseSpeakerText( binary.SpeakerTableHeader.SpeakerNameArray
                                        .Value[binaryMessage.SpeakerId].Value, instance.FormatVersion, encoding == null ? Encoding.ASCII : encoding );
                                }

                                message = new MessageDialog( binaryMessage.Name, new NamedSpeaker( speakerName ) );
                            }
                        }
                        break;

                    case BinaryDialogKind.Selection:
                        {
                            var binaryMessage = ( BinarySelectionDialog )messageHeader.Dialog.Value;
                            pageStartAddresses = binaryMessage.OptionStartAddresses;
                            buffer = binaryMessage.TextBuffer;
                            pageCount = binaryMessage.OptionCount;

                            message = new SelectionDialog( ( string )binaryMessage.Name.Clone() );
                        }
                        break;

                    default:
                        throw new InvalidDataException( "Unknown message type" );
                }

                if ( pageCount != 0 )
                {
                    // Parse the line data
                    ParsePages( message, pageStartAddresses, buffer, instance.FormatVersion, encoding == null ? Encoding.ASCII : encoding );
                }

                // Add it to the message list
                instance.Dialogs.Add( message );
            }

            return instance;
        }

        /// <summary>
        /// Deserializes and creates a <see cref="MessageScript"/> from a file.
        /// </summary>
        public static MessageScript FromFile( string path, FormatVersion version = FormatVersion.Version1, Encoding encoding = null )
        {
            if ( path == null )
                throw new ArgumentNullException( nameof( path ) );

            var binary = MessageScriptBinary.FromFile( path );

            return FromBinary( binary, version, encoding );
        }

        /// <summary>
        /// Deserializes and creates a <see cref="MessageScript"/> from a stream.
        /// </summary>
        public static MessageScript FromStream( Stream stream, FormatVersion version = FormatVersion.Version1, Encoding encoding = null, bool leaveOpen = false )
        {
            if ( stream == null )
                throw new ArgumentNullException( nameof( stream ) );

            var binary = MessageScriptBinary.FromStream( stream, leaveOpen );

            return FromBinary( binary, version, encoding );
        }

        private static void ParsePages( IDialog message, IReadOnlyList<int> lineStartAddresses, IReadOnlyList<byte> buffer, FormatVersion version, Encoding encoding )
        {
            if ( lineStartAddresses.Count == 0 || buffer.Count == 0 )
                return;

            // The addresses are not relative to the start of the buffer
            // so we rebase the addresses first
            int lineStartAddressBase = lineStartAddresses[0];
            int[] rebasedLineStartAddresses = new int[lineStartAddresses.Count];

            for ( int i = 0; i < lineStartAddresses.Count; i++ )
                rebasedLineStartAddresses[i] = lineStartAddresses[i] - lineStartAddressBase;

            for ( int lineIndex = 0; lineIndex < rebasedLineStartAddresses.Length; lineIndex++ )
            {
                // Initialize a new line
                var line = new TokenText();

                // Now that the line start addresses have been rebased, we can use them as indices into the buffer
                int bufferIndex = rebasedLineStartAddresses[lineIndex];

                // Calculate the line end index
                int lineEndIndex = ( lineIndex + 1 ) != rebasedLineStartAddresses.Length ? rebasedLineStartAddresses[lineIndex + 1] : buffer.Count;

                // Loop over the buffer until we find a 0 byte or have reached the end index
                while ( bufferIndex < lineEndIndex )
                {
                    if ( !TryParseTokens( buffer, ref bufferIndex, out var tokens, version, encoding ) )
                        break;

                    line.Tokens.AddRange( tokens );
                }

                // Add line to list of lines
                message.Lines.Add( line );
            }
        }

        private static TokenText ParseSpeakerText( IReadOnlyList<byte> bytes, FormatVersion version, Encoding encoding )
        {
            var line = new TokenText();

            int bufferIndex = 0;

            while ( bufferIndex < bytes.Count )
            {
                if ( !TryParseTokens( bytes, ref bufferIndex, out var tokens, version, encoding ) )
                    break;

                line.Tokens.AddRange( tokens );
            }

            return line;
        }

        private static bool TryParseTokens( IReadOnlyList<byte> buffer, ref int bufferIndex, out List<IToken> tokens, FormatVersion version, Encoding encoding )
        {
            byte b = buffer[bufferIndex++];
            tokens = new List<IToken>();

            // Check if the current byte signifies a function
            if ( b == 0 )
            {
                tokens = null;
                return false;
            }
            if ( b == NewLineToken.Value )
            {
                tokens.Add( new NewLineToken() );
            }
            else if ( ( b & 0xF0 ) == 0xF0 )
            {
                tokens.Add( ParseFunctionToken( b, buffer, ref bufferIndex, version ) );
            }
            else
            {
                tokens.AddRange( ParseTextTokens( b, buffer, ref bufferIndex, encoding ) );
            }

            return true;
        }

        private static FunctionToken ParseFunctionToken( byte b, IReadOnlyList<byte> buffer, ref int bufferIndex, FormatVersion version )
        {
            int functionId = ( b << 8 ) | buffer[bufferIndex++];
            int functionTableIndex = ( functionId & 0xE0 ) >> 5;
            int functionIndex = ( functionId & 0x1F );

            int functionArgumentByteCount;
            if ( version == FormatVersion.Version1 || version == FormatVersion.Version1BigEndian )
            {
                functionArgumentByteCount = ( ( ( ( functionId >> 8 ) & 0xF ) - 1 ) * 2 );
            }
            else if ( version == FormatVersion.Version1DDS )
            {
                functionArgumentByteCount = ( ( functionId >> 8 ) & 0xF );
            }
            else
            {
                throw new ArgumentOutOfRangeException( nameof( version ) );
            }

            short[] functionArguments = new short[functionArgumentByteCount / 2];

            for ( int i = 0; i < functionArguments.Length; i++ )
            {
                byte firstByte = ( byte )( buffer[bufferIndex++] - 1 );
                byte secondByte = 0;
                byte secondByteAux = buffer[bufferIndex++];

                //if (secondByteAux != 0xFF)
                {
                    secondByte = ( byte )( secondByteAux - 1 );
                }

                functionArguments[i] = ( short )( ( firstByte & ~0xFF00 ) | ( ( secondByte << 8 ) & 0xFF00 ) );
            }

            return new FunctionToken( functionTableIndex, functionIndex, functionArguments );
        }

        private static IEnumerable< IToken > ParseTextTokens( byte b, IReadOnlyList<byte> buffer, ref int bufferIndex, Encoding encoding )
        {
            var accumulatedText = new List<byte>();
            var charBytes = new byte[2];
            var tokens = new List<IToken>();
            byte b2;

            while ( true )
            {
                // Read 2 bytes
                if ( ( b & 0x80 ) == 0x80 )
                {
                    b2 = buffer[bufferIndex++];
                    accumulatedText.Add( b );
                    accumulatedText.Add( b2 );
                }
                else
                {
                    // Read one
                    accumulatedText.Add( b );
                }

                // Check for any condition that would end the sequence of text characters
                if ( bufferIndex == buffer.Count )
                    break;

                b = buffer[bufferIndex];

                if ( b == 0 || b == NewLineToken.Value || ( b & 0xF0 ) == 0xF0 )
                {                 
                    break;
                }

                bufferIndex++;
            }

            var accumulatedTextBuffer = accumulatedText.ToArray();
            var stringBuilder = new StringBuilder();

            void FlushStringBuilder()
            {
                // There was some proper text previously, so make sure we add it first
                if ( stringBuilder.Length != 0 )
                {
                    tokens.Add( new StringToken( stringBuilder.ToString() ) );
                    stringBuilder.Clear();
                }
            }

            void AddToken( CodePointToken token )
            {
                FlushStringBuilder();
                tokens.Add( token );
            }

            for ( int i = 0; i < accumulatedTextBuffer.Length; i++ )
            {
                byte high = accumulatedTextBuffer[i];
                if ( ( high & 0x80 ) == 0x80 )
                {
                    byte low = accumulatedTextBuffer[++i];

                    if ( encoding != null && !encoding.IsSingleByte )
                    {
                        // Get decoded characters
                        charBytes[0] = high;
                        charBytes[1] = low;

                        // Check if it's an unmapped character -> make it a code point
                        var chars = encoding.GetChars( charBytes );
                        Trace.Assert( chars.Length > 0 );

                        if ( chars[0] == 0 )
                        {
                            AddToken( new CodePointToken( high, low ) );
                        }
                        else
                        {
                            foreach ( char c in chars )
                            {
                                stringBuilder.Append( c );
                            }
                        }
                    }
                    else
                    {
                        AddToken( new CodePointToken( high, low ) );
                    }
                }
                else
                {
                    stringBuilder.Append( ( char )high );
                }
            }

            FlushStringBuilder();

            return tokens;
        }

        /// <summary>
        /// Gets or sets the user id. Serves as metadata.
        /// </summary>
        public short Id { get; set; }

        /// <summary>
        /// Gets or sets the format version this script will use in its binary form.
        /// </summary>
        public FormatVersion FormatVersion { get; set; }

        /// <summary>
        /// Gets or sets the encoding used for the text.
        /// </summary>
        public Encoding Encoding { get; set; }

        /// <summary>
        /// Gets the list of <see cref="IDialog"/> in this script.
        /// </summary>
        public List<IDialog> Dialogs { get; }

        /// <summary>
        /// Creates a new instance of <see cref="MessageScript"/> initialized with default values.
        /// </summary>
        private MessageScript()
        {
            Id = 0;
            FormatVersion = FormatVersion.Version1;
            Encoding = null;
            Dialogs = new List<IDialog>();
        }

        /// <summary>
        /// Creates a new instance of <see cref="MessageScript"/> initialized with default values.
        /// </summary>
        public MessageScript( FormatVersion version, Encoding encoding = null )
        {
            Id = 0;
            FormatVersion = version;
            Encoding = encoding;
            Dialogs = new List<IDialog>();
        }

        /// <summary>
        /// Converts this <see cref="MessageScript"/> instance to a <see cref="MessageScriptBinary"/> instance.
        /// </summary>
        /// <returns></returns>
        public MessageScriptBinary ToBinary()
        {
            var builder = new MessageScriptBinaryBuilder( ( BinaryFormatVersion )FormatVersion );

            builder.SetUserId( Id );
            builder.SetEncoding( Encoding );

            foreach ( var dialog in Dialogs )
            {
                switch ( dialog.Kind )
                {
                    case DialogKind.Message:
                        builder.AddDialog( ( MessageDialog )dialog );
                        break;
                    case DialogKind.Selection:
                        builder.AddDialog( ( SelectionDialog )dialog );
                        break;

                    default:
                        throw new NotImplementedException( dialog.Kind.ToString() );
                }
            }

            return builder.Build();
        }

        /// <summary>
        /// Serializes and writes this <see cref="MessageScript"/> instance to the specified file.
        /// </summary>
        /// <param name="path"></param>
        public void ToFile( string path )
        {
            if ( path == null )
                throw new ArgumentNullException( nameof( path ) );

            if ( string.IsNullOrEmpty( path ) )
                throw new ArgumentException( "Value cannot be null or empty.", nameof( path ) );

            using ( var stream = FileUtils.Create( path ) )
                ToStream( stream );
        }

        /// <summary>
        /// Serializes and writes this <see cref="MessageScript"/> instance to a stream.
        /// </summary>
        /// <returns></returns>
        public Stream ToStream()
        {
            var stream = new MemoryStream();
            ToStream( stream, true );
            return stream;
        }

        /// <summary>
        /// Serializes and writes this <see cref="MessageScript"/> instance to the specified stream.
        /// </summary>
        /// <param name="stream">The stream to write to.</param>
        /// <param name="leaveOpen">Whether to stream should be left open or not.</param>
        public void ToStream( Stream stream, bool leaveOpen = false )
        {
            var binary = ToBinary();
            binary.ToStream( stream, leaveOpen );
        }
    }
}
