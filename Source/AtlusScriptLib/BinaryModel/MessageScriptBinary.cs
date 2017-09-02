using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using AtlusScriptLib.BinaryModel.IO;

namespace AtlusScriptLib.BinaryModel
{
    public class MessageScriptBinary
    {
        public static MessageScriptBinary FromFile( string path )
        {
            if ( path == null )
                throw new ArgumentNullException( nameof( path ) );

            if ( string.IsNullOrEmpty( path ) )
                throw new ArgumentException( "Value cannot be null or empty.", nameof( path ) );

            return FromFile( path, MessageScriptBinaryFormatVersion.Unknown );
        }

        public static MessageScriptBinary FromFile( string path, MessageScriptBinaryFormatVersion version )
        {
            if ( path == null )
                throw new ArgumentNullException( nameof( path ) );

            if ( string.IsNullOrEmpty( path ) )
                throw new ArgumentException( "Value cannot be null or empty.", nameof( path ) );

            if ( !Enum.IsDefined( typeof( MessageScriptBinaryFormatVersion ), version ) )
                throw new InvalidEnumArgumentException( nameof( version ), ( int )version,
                    typeof( MessageScriptBinaryFormatVersion ) );

            using ( var fileStream = File.OpenRead( path ) )
                return FromStream( fileStream, version );
        }

        public static MessageScriptBinary FromStream( Stream stream, bool leaveOpen = false )
        {
            if ( stream == null )
                throw new ArgumentNullException( nameof( stream ) );

            return FromStream( stream, MessageScriptBinaryFormatVersion.Unknown, leaveOpen );
        }

        public static MessageScriptBinary FromStream( Stream stream, MessageScriptBinaryFormatVersion version, bool leaveOpen = false )
        {
            if ( stream == null )
                throw new ArgumentNullException( nameof( stream ) );

            if ( !Enum.IsDefined( typeof( MessageScriptBinaryFormatVersion ), version ) )
                throw new InvalidEnumArgumentException( nameof( version ), ( int )version,
                    typeof( MessageScriptBinaryFormatVersion ) );

            using ( var reader = new MessageScriptBinaryReader( stream, version, leaveOpen ) )
            {
                return reader.ReadBinary();
            }
        }

        // these fields are internal because they are used by the builder, reader & writer
        internal MessageScriptBinaryHeader mHeader;
        internal MessageScriptBinaryMessageHeader[] mMessageHeaders;
        internal MessageScriptBinarySpeakerTableHeader mSpeakerTableHeader;
        internal MessageScriptBinaryFormatVersion mFormatVersion;

        public MessageScriptBinaryHeader Header => mHeader;

        public ReadOnlyCollection<MessageScriptBinaryMessageHeader> MessageHeaders
            => new ReadOnlyCollection<MessageScriptBinaryMessageHeader>( mMessageHeaders );

        public MessageScriptBinarySpeakerTableHeader SpeakerTableHeader => mSpeakerTableHeader;

        public MessageScriptBinaryFormatVersion FormatVersion => mFormatVersion;

        // this constructor is internal because it is used by the builder, reader & writer
        internal MessageScriptBinary()
        {
        }

        public void ToFile( string path )
        {
            if ( path == null )
                throw new ArgumentNullException( nameof( path ) );

            if ( string.IsNullOrEmpty( path ) )
                throw new ArgumentException( "Value cannot be null or empty.", nameof( path ) );

            using ( var stream = File.Create( path ) )
                ToStream( stream );
        }

        public Stream ToStream()
        {
            var stream = new MemoryStream();
            ToStream( stream, true );
            return stream;
        }

        public void ToStream( Stream stream, bool leaveOpen = false )
        {
            using ( var writer = new MessageScriptBinaryWriter( stream, mFormatVersion, leaveOpen ) )
            {
                writer.WriteBinary( this );
            }
        }
    }
}
